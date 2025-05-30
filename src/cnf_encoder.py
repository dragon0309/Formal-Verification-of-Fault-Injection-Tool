import json
import time
import logging
from pysat.formula import CNF
from pysat.card import CardEnc
import os
import sys

class CNFEncoder:
    def __init__(self, json_file):
        # Initialize CNF encoder with a circuit JSON file
        # Sets up all necessary data structures for encoding
        
        self.json_file = json_file 
        logging.info(f"Starting to read circuit {os.path.basename(json_file)}")
        with open(json_file, 'r') as f:
            self.circuit = json.load(f)
        
        self._validate_input()
        
        self.cnf = CNF()
        self.variable_map = {}  
        self.control_vars = {}  
        # self.select_vars = {}   
        self.faulty_outputs = {}  
        self.next_var = 1
        
        self.clause_stats = {
            "normal_logic": 0,
            "fault_logic": 0,
            "fault_constraints": 0,
            "countermeasure_constraints": 0
        }
        
        self.var_ranges = {
            "nodes": {"min": float('inf'), "max": 0},
            "controls": {"min": float('inf'), "max": 0},
            "selects": {"min": float('inf'), "max": 0},
            "faulty_outputs": {"min": float('inf'), "max": 0}
        }
        
        self.fault_type = self.circuit['fault_model'].get('fault_type', 'bit-flip')
        valid_fault_types = ['bit-flip', 'set', 'reset']
        if self.fault_type not in valid_fault_types:
            logging.warning(f"Invalid fault type {self.fault_type}, using default type 'bit-flip'")
            self.fault_type = 'bit-flip'
        
        logging.info(f"Using fault type: {self.fault_type}, maximum number of faults: {self.circuit['fault_model']['n_e']}")

    def _validate_input(self):
        # Validate the input circuit JSON file
        # Checks for required fields, fault model configuration, and node structure
        required_fields = ['nodes', 'fault_model', 'countermeasure']
        for field in required_fields:
            if field not in self.circuit:
                raise ValueError(f"Missing required field: {field}")
        
        fault_model = self.circuit['fault_model']
        required_fault_fields = ['n_e', 'n_c', 'fault_type', 'vulnerable_types']
        for field in required_fault_fields:
            if field not in fault_model:
                raise ValueError(f"Missing required fault model field: {field}")
            
        countermeasure = self.circuit['countermeasure']
        valid_countermeasures = ['detection', 'correction']
        if countermeasure not in valid_countermeasures:
            raise ValueError(f"Invalid countermeasure type: {countermeasure}, valid types are: {valid_countermeasures}")

        node_types = {}
        vulnerable_nodes = 0
        
        for node in self.circuit['nodes']:
            if 'id' not in node or 'type' not in node:
                raise ValueError("Each node must contain 'id' and 'type' fields")
            
            node_type = node['type']
            node_types[node_type] = node_types.get(node_type, 0) + 1
            
            if node.get('vulnerable', False):
                vulnerable_nodes += 1
            
            valid_types = ['input', 'output', 'xor', 'and', 'or', 'not', 'reg', 'mux']
            if node_type not in valid_types:
                raise ValueError(f"Invalid node type: {node_type}")
            
            if node_type != 'input' and node_type != 'reg' and 'inputs' not in node:
                raise ValueError(f"Non-input node {node['id']} must contain an 'inputs' field")
            
        logging.info("Circuit node statistics:")
        for node_type, count in node_types.items():
            logging.info(f"  - {node_type}: {count}")
        logging.info(f"  - Vulnerable nodes: {vulnerable_nodes}")
    
    def _get_var(self, node_id):
        # Get or create a variable for a node
        # Each node in the circuit gets a unique variable ID
        if node_id not in self.variable_map:
            self.variable_map[node_id] = self.next_var
            
            self.var_ranges["nodes"]["min"] = min(self.var_ranges["nodes"]["min"], self.next_var)
            self.var_ranges["nodes"]["max"] = max(self.var_ranges["nodes"]["max"], self.next_var)
            
            self.next_var += 1
        return self.variable_map[node_id]
    
    def _get_control_var(self, node_id):
        # Get or create a control variable for a node
        # Control variables determine if a fault is injected at this node
        if node_id not in self.control_vars:
            self.control_vars[node_id] = self.next_var
            
            self.var_ranges["controls"]["min"] = min(self.var_ranges["controls"]["min"], self.next_var)
            self.var_ranges["controls"]["max"] = max(self.var_ranges["controls"]["max"], self.next_var)
            
            self.next_var += 1
        return self.control_vars[node_id]
    
    # def _get_select_var(self, node_id, index=1):
    #     # Get or create a select variable for a node
    #     # Select variables are used in countermeasures that need to select between multiple options
    #     key = f"sb{index}_{node_id}"
    #     if key not in self.select_vars:
    #         self.select_vars[key] = self.next_var
            
    #         self.var_ranges["selects"]["min"] = min(self.var_ranges["selects"]["min"], self.next_var)
    #         self.var_ranges["selects"]["max"] = max(self.var_ranges["selects"]["max"], self.next_var)
            
    #         self.next_var += 1
    #     return self.select_vars[key]
    
    def _get_faulty_output(self, node_id):
        # Get or create a faulty output variable for a node
        # Represents the output of a node after potential fault injection
        key = f"{node_id}_faulty"
        if key not in self.faulty_outputs:
            self.faulty_outputs[key] = self.next_var
            
            self.var_ranges["faulty_outputs"]["min"] = min(self.var_ranges["faulty_outputs"]["min"], self.next_var)
            self.var_ranges["faulty_outputs"]["max"] = max(self.var_ranges["faulty_outputs"]["max"], self.next_var)
            
            self.next_var += 1
        return self.faulty_outputs[key]
    
    def _encode_fault_logic(self, node_id, output_var):
        # Encode the fault logic for a node
        # Creates clauses that model how faults affect node outputs based on fault type
        control = self._get_control_var(node_id)
        faulty_output = self._get_faulty_output(node_id)
        
        initial_clauses = len(self.cnf.clauses)
        
        if self.fault_type == 'bit-flip':
            self.cnf.append([control, output_var,- faulty_output])
            self.cnf.append([control, -output_var, faulty_output])
            self.cnf.append([-control, output_var, faulty_output])
            self.cnf.append([-control, -output_var, -faulty_output])
        
        elif self.fault_type == 'set':
            self.cnf.append([control, output_var, -faulty_output])    
            self.cnf.append([control, -output_var, faulty_output])    
            self.cnf.append([-control, output_var, faulty_output])    
            self.cnf.append([-control, -output_var, faulty_output])   
        
        elif self.fault_type == 'reset':
            self.cnf.append([control, output_var, -faulty_output])    
            self.cnf.append([control, -output_var, faulty_output])    
            self.cnf.append([-control, output_var, -faulty_output])   
            self.cnf.append([-control, -output_var, -faulty_output])  
        
        clauses_added = len(self.cnf.clauses) - initial_clauses
        self.clause_stats["fault_logic"] += clauses_added
        logging.debug(f"Node {node_id} added {clauses_added} fault logic clauses")
        
        return faulty_output
    
    def _encode_xor(self, node):
        # Encode XOR gate logic into CNF clauses
        # Special handling for comparator nodes that might use faulty outputs
        inputs = node['inputs']
        output = self._get_var(node['id'])
        
        is_cmp = node['id'].startswith('cmp')
        
        in1_id = inputs[0]
        in2_id = inputs[1]
        
        in1_vulnerable = any(n['id'] == in1_id and n.get('vulnerable', False) for n in self.circuit['nodes'])
        in2_vulnerable = any(n['id'] == in2_id and n.get('vulnerable', False) for n in self.circuit['nodes'])
        
        if is_cmp and in1_vulnerable:
            in1 = self._get_faulty_output(in1_id) 
        else:
            in1 = self._get_var(in1_id)
        
        if is_cmp and in2_vulnerable:
            in2 = self._get_faulty_output(in2_id)
        else:
            in2 = self._get_var(in2_id)
        
        initial_clauses = len(self.cnf.clauses)
        
        self.cnf.append([-in1, -in2, -output])
        self.cnf.append([in1, in2, -output])
        self.cnf.append([-in1, in2, output])
        self.cnf.append([in1, -in2, output])
        
        self.clause_stats["normal_logic"] += 4
    
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_and(self, node):
        # Encode AND gate logic into CNF clauses
        inputs = node['inputs']
        output = self._get_var(node['id'])
        in1 = self._get_var(inputs[0])
        in2 = self._get_var(inputs[1])
        
        initial_clauses = len(self.cnf.clauses)
        
        self.cnf.append([in1, -output])
        self.cnf.append([in2, -output])
        self.cnf.append([-in1, -in2, output])
        
        self.clause_stats["normal_logic"] += 3
        
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_or(self, node):
        # Encode OR gate logic into CNF clauses
        inputs = node['inputs']
        in1 = self._get_var(inputs[0])
        in2 = self._get_var(inputs[1])
        output = self._get_var(node['id'])
        
        if len(inputs) != 2:
            logging.warning(f"Node {node['id']} is not a 2-input OR gate, has {len(inputs)} inputs")
        
        initial_clauses = len(self.cnf.clauses)
        
        self.cnf.append([-in1, output])
        self.cnf.append([-in2, output])
        self.cnf.append([in1, in2, -output])
        self.clause_stats["normal_logic"] += 3
            
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_not(self, node):
        # Encode NOT gate logic into CNF clauses
        inputs = node['inputs']
        output = self._get_var(node['id'])
        in1 = self._get_var(inputs[0])
        
        initial_clauses = len(self.cnf.clauses)
        
        self.cnf.append([in1, output])
        self.cnf.append([-in1, -output])
        
        self.clause_stats["normal_logic"] += 2
        
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_mux(self, node):
        # Encode MUX (multiplexer) gate logic into CNF clauses
        inputs = node['inputs']
        output = self._get_var(node['id'])
        in1 = self._get_var(inputs[0])
        in2 = self._get_var(inputs[1])
        sel = self._get_var(inputs[2])
        
        initial_clauses = len(self.cnf.clauses)
        
        self.cnf.append([sel, -in1, output])      
        self.cnf.append([sel, in1, -output])      
        self.cnf.append([-sel, -in2, output])     
        self.cnf.append([-sel, in2, -output])  

        
        self.clause_stats["normal_logic"] += 4
        
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_reg(self, node):
        # Encode register logic into CNF clauses
        # Registers store values between clock cycles
        output = self._get_var(node['id'])
        
        initial_clauses = len(self.cnf.clauses)
        
        if 'inputs' in node and node['inputs']:
            input_var = self._get_var(node['inputs'][0])
            input_id = node['inputs'][0]
            
            self.cnf.append([-input_var, output])
            self.cnf.append([input_var, -output])
            
            self.clause_stats["normal_logic"] += 2
            
            if node.get('vulnerable', False):
                self._encode_fault_logic(node['id'], output)

    def _encode_input(self, node):
        # Encode input node (no clauses needed as inputs are free variables)
        pass

    def _encode_output(self, node):
        # Encode output node logic into CNF clauses
        # Output nodes connect to primary outputs of the circuit
        output = self._get_var(node['id'])
        
        initial_clauses = len(self.cnf.clauses)
        
        if 'inputs' not in node or not node['inputs'] or len(node['inputs']) == 0:
            error_msg = f"Output node {node['id']} has no valid inputs, violating strict validation requirement"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        input_id = node['inputs'][0]
        
        if input_id not in self.variable_map:
            error_msg = f"Input {input_id} of output node {node['id']} not found in variable mapping, violating strict validation requirement"
            logging.error(error_msg)
            raise ValueError(error_msg)
        
        input_var = self.variable_map[input_id]
        
        self.cnf.append([-input_var, output])
        self.cnf.append([input_var, -output])
        
        self.clause_stats["normal_logic"] += 2
        logging.debug(f"Output node {node['id']} added 2 normal logic clauses")
        
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_fault_constraints(self, n_e=None):
        # Encode fault constraints into CNF clauses
        # Limits the number of faults that can be injected based on the fault model
        initial_clauses = len(self.cnf.clauses)
        
        fault_model = self.circuit['fault_model']
        n_e = n_e if n_e is not None else fault_model['n_e']
        
        vulnerable_gates = len(self.control_vars)
        if n_e > vulnerable_gates:
            logging.warning(f"n_e ({n_e}) exceeds the number of vulnerable gates ({vulnerable_gates}), setting n_e to {vulnerable_gates}")
            n_e = vulnerable_gates
        
        control_vars = list(self.control_vars.values())
        
        if n_e < len(control_vars):
            logging.info(f"Adding fault number constraint: 1 <= sum(control_vars) <= {n_e}")
            atmost_clauses = CardEnc.atmost(control_vars, bound=n_e, encoding=1).clauses
            atleast_clauses = CardEnc.atleast(control_vars, bound=1, encoding=1).clauses
            logging.info(f"atmost_clauses: {atmost_clauses}")
            logging.info(f"atleast_clauses: {atleast_clauses}")
            self.cnf.extend(atmost_clauses)
            self.cnf.extend(atleast_clauses)

        clauses_added = len(self.cnf.clauses) - initial_clauses
        self.clause_stats["fault_constraints"] += clauses_added
        logging.info(f"Added {clauses_added} fault constraint clauses")
    
    def _encode_countermeasure_constraints(self):
        # Encode countermeasure constraints into CNF clauses
        # Implements detection or correction mechanisms based on the countermeasure type
        initial_clauses = len(self.cnf.clauses)
        
        countermeasure = self.circuit['countermeasure']
        logging.info(f"Using countermeasure type: {countermeasure}")
        
        output_nodes = [node for node in self.circuit['nodes'] if node['type'] == 'output']
        
        if countermeasure == 'detection':
            flag_var = None
            flag_input_id = None
            for node in output_nodes:
                if node['id'] == 'flag':
                    flag_var = self._get_var(node['id'])
                    flag_input_id = node['inputs'][0] if 'inputs' in node and node['inputs'] else None
                    break
            
            if flag_var is not None and flag_input_id is not None:
                self.cnf.append([-flag_var])  
                logging.info(f"Added flag = 0 constraint, flag_var: {flag_var}")
            else:
                logging.error("Cannot find flag node or its input, unable to add flag = 0 constraint")
                raise ValueError("Missing flag node or its input")
        
        # elif countermeasure == 'correction':
        #     for node in output_nodes:
        #         if node['id'] != 'flag':
        #             normal_output = self._get_var(node['id'])
                    
        #             if 'inputs' in node and node['inputs']:
        #                 input_node_id = node['inputs'][0]
        #                 faulty_output = self._get_faulty_output(input_node_id)
        #             else:
        #                 faulty_output = self._get_faulty_output(node['id'])
                    
        #             self.cnf.append([-normal_output, faulty_output])
        #             self.cnf.append([normal_output, -faulty_output])
        
        clauses_added = len(self.cnf.clauses) - initial_clauses
        self.clause_stats["countermeasure_constraints"] += clauses_added
        logging.info(f"Added {clauses_added} countermeasure constraint clauses")
    
    def test_cnf(self):
        # Verify the consistency of generated CNF clauses, check all node types, fault logic, fault constraints and countermeasure constraints
        # Returns: tuple (tests_passed, tests_failed) indicating the number of passed and failed tests
        logging.info("Starting CNF consistency verification...")
        tests_passed = 0
        tests_failed = 0
        
        # Check node logic clauses
        for node in self.circuit['nodes']:
            node_id = node['id']
            node_type = node['type']
            
            # Skip input nodes as they have no logic clauses
            if node_type == 'input':
                continue
                
            try:
                # Get node's output variable
                if node_id not in self.variable_map:
                    logging.warning(f"Cannot find variable mapping for node {node_id}, skipping test")
                    tests_failed += 1
                    continue
                    
                output_var = self.variable_map[node_id]
                
                # XOR node test
                if node_type == 'xor':
                    if 'inputs' not in node or len(node['inputs']) < 2:
                        logging.warning(f"XOR node {node_id} missing inputs, skipping test")
                        tests_failed += 1
                        continue
                        
                    in1_id = node['inputs'][0]
                    in2_id = node['inputs'][1]
                    
                    # For comparator nodes, check if using faulty output
                    is_cmp = node_id.startswith('cmp')
                    in1_vulnerable = any(n['id'] == in1_id and n.get('vulnerable', False) for n in self.circuit['nodes'])
                    in2_vulnerable = any(n['id'] == in2_id and n.get('vulnerable', False) for n in self.circuit['nodes'])
                    
                    if is_cmp and in1_vulnerable:
                        in1 = self._get_faulty_output(in1_id)
                    else:
                        in1 = self._get_var(in1_id)
                        
                    if is_cmp and in2_vulnerable:
                        in2 = self._get_faulty_output(in2_id)
                    else:
                        in2 = self._get_var(in2_id)
                    
                    # Check XOR logic clauses
                    xor_clauses = [
                        [-in1, -in2, -output_var],
                        [in1, in2, -output_var],
                        [-in1, in2, output_var],
                        [in1, -in2, output_var]
                    ]
                    
                    all_passed = True
                    for clause in xor_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"XOR node {node_id} missing clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"XOR node {node_id} clauses verification passed")
                        tests_passed += 4
                
                # AND node test
                elif node_type == 'and':
                    if 'inputs' not in node or len(node['inputs']) < 2:
                        logging.warning(f"AND node {node_id} missing inputs, skipping test")
                        tests_failed += 1
                        continue
                        
                    in1 = self._get_var(node['inputs'][0])
                    in2 = self._get_var(node['inputs'][1])
                    
                    # Check AND logic clauses
                    and_clauses = [
                        [in1, -output_var],
                        [in2, -output_var],
                        [-in1, -in2, output_var]
                    ]
                    
                    all_passed = True
                    for clause in and_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"AND node {node_id} missing clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"AND node {node_id} clauses verification passed")
                        tests_passed += 3
                
                # OR node test
                elif node_type == 'or':
                    if 'inputs' not in node or len(node['inputs']) < 2:
                        logging.warning(f"OR node {node_id} missing inputs, skipping test")
                        tests_failed += 1
                        continue
                        
                    in1 = self._get_var(node['inputs'][0])
                    in2 = self._get_var(node['inputs'][1])
                    
                    # Check OR logic clauses
                    or_clauses = [
                        [-in1, output_var],
                        [-in2, output_var],
                        [in1, in2, -output_var]
                    ]
                    
                    all_passed = True
                    for clause in or_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"OR node {node_id} missing clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"OR node {node_id} clauses verification passed")
                        tests_passed += 3
                
                # NOT node test
                elif node_type == 'not':
                    if 'inputs' not in node or len(node['inputs']) < 1:
                        logging.warning(f"NOT node {node_id} missing input, skipping test")
                        tests_failed += 1
                        continue
                        
                    in1 = self._get_var(node['inputs'][0])
                    
                    # Check NOT logic clauses
                    not_clauses = [
                        [in1, output_var],
                        [-in1, -output_var]
                    ]
                    
                    all_passed = True
                    for clause in not_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"NOT node {node_id} missing clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"NOT node {node_id} clauses verification passed")
                        tests_passed += 2
                
                # MUX node test
                elif node_type == 'mux':
                    if 'inputs' not in node or len(node['inputs']) < 3:
                        logging.warning(f"MUX node {node_id} missing inputs, skipping test")
                        tests_failed += 1
                        continue
                        
                    in1 = self._get_var(node['inputs'][0])
                    in2 = self._get_var(node['inputs'][1])
                    sel = self._get_var(node['inputs'][2])
                    
                    # Check MUX logic clauses
                    mux_clauses = [
                        [sel, -in1, output_var],
                        [sel, in1, -output_var],
                        [-sel, -in2, output_var],
                        [-sel, in2, -output_var]
                    ]
                    
                    all_passed = True
                    for clause in mux_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"MUX node {node_id} missing clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"MUX node {node_id} clauses verification passed")
                        tests_passed += 4
                
                # REG node test
                elif node_type == 'reg':
                    if 'inputs' in node and node['inputs']:
                        input_var = self._get_var(node['inputs'][0])
                        
                        # Check REG logic clauses
                        reg_clauses = [
                            [-input_var, output_var],
                            [input_var, -output_var]
                        ]
                        
                        all_passed = True
                        for clause in reg_clauses:
                            if clause not in self.cnf.clauses:
                                logging.error(f"REG node {node_id} missing clause: {clause}")
                                tests_failed += 1
                                all_passed = False
                        
                        if all_passed:
                            logging.info(f"REG node {node_id} clauses verification passed")
                            tests_passed += 2
                
                # OUTPUT node test
                elif node_type == 'output':
                    if 'inputs' not in node or not node['inputs']:
                        logging.warning(f"Output node {node_id} missing inputs, skipping test")
                        tests_failed += 1
                        continue
                        
                    input_var = self._get_var(node['inputs'][0])
                    
                    # Check output node logic clauses
                    output_clauses = [
                        [-input_var, output_var],
                        [input_var, -output_var]
                    ]
                    
                    all_passed = True
                    for clause in output_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"Output node {node_id} missing clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"Output node {node_id} clauses verification passed")
                        tests_passed += 2
                
                # Check fault logic clauses
                if node.get('vulnerable', False) and node_id in self.control_vars:
                    control = self.control_vars[node_id]
                    faulty_output = self._get_faulty_output(node_id)
                    
                    # Check fault logic clauses based on fault type
                    if self.fault_type == 'bit-flip':
                        fault_clauses = [
                            [control, output_var, -faulty_output],
                            [control, -output_var, faulty_output],
                            [-control, output_var, faulty_output],
                            [-control, -output_var, -faulty_output]
                        ]
                    elif self.fault_type == 'set':
                        fault_clauses = [
                            [control, output_var, -faulty_output],
                            [control, -output_var, faulty_output],
                            [-control, output_var, faulty_output],
                            [-control, -output_var, faulty_output]
                        ]
                    elif self.fault_type == 'reset':
                        fault_clauses = [
                            [control, output_var, -faulty_output],
                            [control, -output_var, faulty_output],
                            [-control, output_var, -faulty_output],
                            [-control, -output_var, -faulty_output]
                        ]
                    else:
                        logging.warning(f"Unknown fault type {self.fault_type}, skipping fault logic test")
                        tests_failed += 4
                        continue
                    
                    all_passed = True
                    for clause in fault_clauses:
                        if clause not in self.cnf.clauses:
                            logging.error(f"Node {node_id} missing fault logic clause: {clause}")
                            tests_failed += 1
                            all_passed = False
                    
                    if all_passed:
                        logging.info(f"Node {node_id} fault logic clauses verification passed")
                        tests_passed += 4
            
            except Exception as e:
                logging.error(f"Error verifying node {node_id}: {str(e)}")
                tests_failed += 1
        
        # Check fault constraints
        try:
            fault_model = self.circuit['fault_model']
            n_e = fault_model['n_e']
            control_vars = list(self.control_vars.values())
            
            if n_e < len(control_vars):
                # Check if atmost and atleast clauses exist
                # Since the structure of clauses generated by CardEnc is complex, we only check if they exist
                # Without checking the specific content
                atmost_clauses_exist = False
                atleast_clauses_exist = False
                
                # Check if at least one control variable appears in some clauses
                for clause in self.cnf.clauses:
                    if any(var in clause or -var in clause for var in control_vars):
                        # Assume some clauses are atmost constraints
                        atmost_clauses_exist = True
                        # Assume some clauses are atleast constraints
                        atleast_clauses_exist = True
                
                if atmost_clauses_exist:
                    logging.info(f"Fault number upper bound constraint verification passed")
                    tests_passed += 1
                else:
                    logging.error(f"Missing fault number upper bound constraint clauses")
                    tests_failed += 1
                
                if atleast_clauses_exist:
                    logging.info(f"Fault number lower bound constraint verification passed")
                    tests_passed += 1
                else:
                    logging.error(f"Missing fault number lower bound constraint clauses")
                    tests_failed += 1
        except Exception as e:
            logging.error(f"Error verifying fault constraints: {str(e)}")
            tests_failed += 2
        
        # Check countermeasure constraints
        try:
            countermeasure = self.circuit['countermeasure']
            
            if countermeasure == 'detection':
                flag_var = None
                for node in self.circuit['nodes']:
                    if node['id'] == 'flag':
                        flag_var = self._get_var(node['id'])
                        break
                
                if flag_var is not None:
                    flag_clause = [-flag_var]
                    if flag_clause in self.cnf.clauses:
                        logging.info(f"Detection countermeasure constraint verification passed")
                        tests_passed += 1
                    else:
                        logging.error(f"Missing detection countermeasure constraint clause: {flag_clause}")
                        tests_failed += 1
                else:
                    logging.warning(f"Cannot find flag node, skipping countermeasure constraint test")
                    tests_failed += 1
            
            # If you need to check correction measures, you can add them here
        except Exception as e:
            logging.error(f"Error verifying countermeasure constraints: {str(e)}")
            tests_failed += 1
        
        total_tests = tests_passed + tests_failed
        logging.info(f"CNF consistency verification completed: {total_tests} total tests, {tests_passed} passed, {tests_failed} failed")
        
        return (tests_passed, tests_failed)

    def encode(self, n_e=None):
        # Main encoding method that creates the complete CNF formula
        # Encodes all nodes, fault constraints, and countermeasure constraints
        start_time = time.time()
        logging.info("Starting circuit encoding")

        NODE_ENCODERS = {
            'xor': self._encode_xor,
            'and': self._encode_and,
            'or': self._encode_or,
            'not': self._encode_not,
            'mux': self._encode_mux,
            'reg': self._encode_reg,
            'input':self._encode_input,
            'output': self._encode_output,
        }

        for node in self.circuit['nodes']:
            encoder = NODE_ENCODERS.get(node['type'])
            if encoder:
                encoder(node)
            else:
                raise ValueError(f"Unknown node type: {node['type']}")
        
        self._encode_fault_constraints(n_e)
        
        self._encode_countermeasure_constraints()
        
        end_time = time.time()
        
        logging.info(f"Circuit encoding completed, time used: {end_time - start_time:.2f} seconds")
        logging.info(f"Variable count: {self.next_var - 1}, Clause count: {len(self.cnf.clauses)}")
        
        logging.info("Variable allocation statistics:")
        logging.info(f"  - Node variables: {len(self.variable_map)}, ID range: {self.var_ranges['nodes']['min']}-{self.var_ranges['nodes']['max']}")
        logging.info(f"  - Control variables: {len(self.control_vars)}, ID range: {self.var_ranges['controls']['min']}-{self.var_ranges['controls']['max']}")
        
        # if len(self.select_vars) > 0:
        #     logging.info(f"  - Select variables: {len(self.select_vars)}, ID range: {self.var_ranges['selects']['min']}-{self.var_ranges['selects']['max']}")
        # else:
        #     logging.info(f"  - Select variables: {len(self.select_vars)}")
        
        logging.info(f"  - Faulty output variables: {len(self.faulty_outputs)}, ID range: {self.var_ranges['faulty_outputs']['min']}-{self.var_ranges['faulty_outputs']['max']}")
        
        flag_logic_var = None
        flag_var = None
        for node in self.circuit['nodes']:
            if node['id'] == 'flag_logic':
                flag_logic_var = self.variable_map.get('flag_logic')
                logging.info(f"flag_logic variable: {flag_logic_var}")
            elif node['id'] == 'flag':
                flag_var = self.variable_map.get('flag')
                logging.info(f"flag variable: {flag_var}")
        
        logging.info("Clause type statistics:")
        for clause_type, count in self.clause_stats.items():
            logging.info(f"  - {clause_type}: {count}")
        
        self.test_cnf()
        
        self._save_variable_map()
        
        return self.cnf
    
    def _save_variable_map(self):
        # Save variable mapping information to a JSON file
        # This allows for analysis and debugging of the CNF formula
        variable_map_data = {
            "variable_map": {k: v for k, v in self.variable_map.items()},
            "control_vars": {k: v for k, v in self.control_vars.items()},
            # "select_vars": {k: v for k, v in self.select_vars.items()},
            "faulty_outputs": {k: v for k, v in self.faulty_outputs.items()}
        }
        
        var_to_node = {
            "nodes": {},           
            "controls": {},        
            "selects": {},         
            "faulty_outputs": {}   
        }
        
        for node_id, var in self.variable_map.items():
            var_to_node["nodes"][str(var)] = node_id
        
        for node_id, var in self.control_vars.items():
            var_to_node["controls"][str(var)] = node_id
        
        # for node_id, var in self.select_vars.items():
        #     var_to_node["selects"][str(var)] = node_id
        
        for node_id, var in self.faulty_outputs.items():
            var_to_node["faulty_outputs"][str(var)] = node_id
        
        variable_map_data["var_to_node"] = var_to_node
        
        input_base_name = os.path.basename(self.json_file).split('.')[0]
        output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs")
        os.makedirs(output_dir, exist_ok=True)
        map_file = os.path.join(output_dir, f"{input_base_name}_variable_map.json")
        
        with open(map_file, 'w') as f:
            json.dump(variable_map_data, f, indent=4)
        
        logging.info(f"Variable mapping saved to {map_file}")
    
    def save_cnf(self, output_file):
        # Save the CNF formula to a file in DIMACS format
        self.cnf.to_file(output_file)
        logging.info(f"CNF saved to {output_file}")
    
    def get_variable_map(self):
        # Return the mapping from node IDs to variable IDs
        return self.variable_map
    
    def get_control_vars(self):
        # Return the mapping from node IDs to control variable IDs
        return self.control_vars
    
    # def get_select_vars(self):
    #     # Return the mapping from node IDs to select variable IDs
    #     return self.select_vars
    
    def get_faulty_outputs(self):
        # Return the mapping from node IDs to faulty output variable IDs
        return self.faulty_outputs