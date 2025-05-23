import json
import time
import logging
from pysat.formula import CNF
from pysat.card import CardEnc
import os
import sys

class CNFEncoder:
    def __init__(self, json_file):
  
        self.json_file = json_file 
        logging.info(f"Starting to read circuit {os.path.basename(json_file)}")
        with open(json_file, 'r') as f:
            self.circuit = json.load(f)
        
        self._validate_input()
        
        self.cnf = CNF()
        self.variable_map = {}  
        self.control_vars = {}  
        self.select_vars = {}   
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
 
        if node_id not in self.variable_map:
            self.variable_map[node_id] = self.next_var
            
            self.var_ranges["nodes"]["min"] = min(self.var_ranges["nodes"]["min"], self.next_var)
            self.var_ranges["nodes"]["max"] = max(self.var_ranges["nodes"]["max"], self.next_var)
            
            self.next_var += 1
        return self.variable_map[node_id]
    
    def _get_control_var(self, node_id):
      
        if node_id not in self.control_vars:
            self.control_vars[node_id] = self.next_var
            
            self.var_ranges["controls"]["min"] = min(self.var_ranges["controls"]["min"], self.next_var)
            self.var_ranges["controls"]["max"] = max(self.var_ranges["controls"]["max"], self.next_var)
            
            self.next_var += 1
        return self.control_vars[node_id]
    
    def _get_select_var(self, node_id, index=1):
      
        key = f"sb{index}_{node_id}"
        if key not in self.select_vars:
            self.select_vars[key] = self.next_var
            
            self.var_ranges["selects"]["min"] = min(self.var_ranges["selects"]["min"], self.next_var)
            self.var_ranges["selects"]["max"] = max(self.var_ranges["selects"]["max"], self.next_var)
            
            self.next_var += 1
        return self.select_vars[key]
    
    def _get_faulty_output(self, node_id):
    
        key = f"{node_id}_faulty"
        if key not in self.faulty_outputs:
            self.faulty_outputs[key] = self.next_var
            
            self.var_ranges["faulty_outputs"]["min"] = min(self.var_ranges["faulty_outputs"]["min"], self.next_var)
            self.var_ranges["faulty_outputs"]["max"] = max(self.var_ranges["faulty_outputs"]["max"], self.next_var)
            
            self.next_var += 1
        return self.faulty_outputs[key]
    
    def _encode_fault_logic(self, node_id, output_var):
       
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
   
        inputs = node['inputs']
        in1 = self._get_var(inputs[0])
        in2 = self._get_var(inputs[1])
        output = self._get_var(node['id'])
        
        if len(inputs) != 2:
            logging.warning(f"節點 {node['id']} 不是2輸入OR閘，有 {len(inputs)} 個輸入")
        
        initial_clauses = len(self.cnf.clauses)
        
        self.cnf.append([-in1, output])
        self.cnf.append([-in2, output])
        self.cnf.append([in1, in2, -output])
        self.clause_stats["normal_logic"] += 3
            
        if node.get('vulnerable', False):
            self._encode_fault_logic(node['id'], output)
    
    def _encode_not(self, node):
     
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
        pass

    def _encode_output(self, node):
    
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
            self.cnf.extend(atmost_clauses)
            self.cnf.extend(atleast_clauses)

        clauses_added = len(self.cnf.clauses) - initial_clauses
        self.clause_stats["fault_constraints"] += clauses_added
        logging.info(f"Added {clauses_added} fault constraint clauses")
    
    def _encode_countermeasure_constraints(self):
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
    
    # def test_cnf(self):
       
    #     logging.info("Starting CNF consistency verification...")
        
    #     tests_passed = 0
    #     tests_failed = 0
        
    #     xor_node = None
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'xor' and 'inputs' in node:
    #             xor_node = node
    #             break
        
    #     if xor_node:
    #         node_id = xor_node['id']
    #         output_var = self.variable_map.get(node_id)
    #         input_ids = xor_node['inputs']
            
    #         if len(input_ids) == 2 and output_var:
    #             in1_var = self.variable_map.get(input_ids[0])
    #             in2_var = self.variable_map.get(input_ids[1])
                
    #             if in1_var and in2_var:
    #                 expected_clauses = [
    #                     [-in1_var, -in2_var, -output_var],
    #                     [in1_var, in2_var, -output_var],
    #                     [-in1_var, in2_var, output_var],
    #                     [in1_var, -in2_var, output_var]
    #                 ]
                    
    #                 all_found = True
    #                 for clause in expected_clauses:
    #                     if clause not in self.cnf.clauses:
    #                         logging.error(f"XOR gate {node_id} missing clause: {clause}")
    #                         all_found = False
    #                         tests_failed += 1
                    
    #                 if all_found:
    #                     logging.info(f"XOR gate {node_id} clause verification passed")
    #                     tests_passed += 1
        
    #     cmp_nodes_tested = 0
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'xor' and node['id'].startswith('cmp'):
    #             node_id = node['id']
    #             output_var = self.variable_map.get(node_id)
    #             input_ids = node['inputs']
                
    #             if len(input_ids) == 2 and output_var:
    #                 in1_var = self.variable_map.get(input_ids[0])
    #                 in2_var = self.variable_map.get(input_ids[1])
                    
    #                 if in1_var and in2_var:
    #                     expected_clauses = [
    #                         [-in1_var, -in2_var, -output_var],
    #                         [in1_var, in2_var, -output_var],
    #                         [-in1_var, in2_var, output_var],
    #                         [in1_var, -in2_var, output_var]
    #                     ]
                        
    #                     all_found = True
    #                     for clause in expected_clauses:
    #                         if clause not in self.cnf.clauses:
    #                             logging.error(f"Comparison gate {node_id} missing clause: {clause}")
    #                             all_found = False
    #                             tests_failed += 1
                        
    #                     if all_found:
    #                         logging.debug(f"Comparison gate {node_id} clause verification passed")
    #                         cmp_nodes_tested += 1
    #                         tests_passed += 1
        
    #     if cmp_nodes_tested > 0:
    #         logging.info(f"Tested {cmp_nodes_tested} comparison gates, all verified")
        
    #     or_nodes_tested = 0
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'or' and 'inputs' in node and len(node['inputs']) == 2:
    #             node_id = node['id']
    #             output_var = self.variable_map.get(node_id)
    #             input_ids = node['inputs']
                
    #             if output_var:
    #                 in1_var = self.variable_map.get(input_ids[0])
    #                 in2_var = self.variable_map.get(input_ids[1])
                    
    #                 if in1_var and in2_var:
    #                     expected_clauses = [
    #                         [in1_var, in2_var, -output_var],
    #                         [-in1_var, output_var],
    #                         [-in2_var, output_var]
    #                     ]
                        
    #                     all_found = True
    #                     for clause in expected_clauses:
    #                         if clause not in self.cnf.clauses:
    #                             logging.error(f"OR gate {node_id} missing clause: {clause}")
    #                             all_found = False
    #                             tests_failed += 1
                        
    #                     if all_found:
    #                         logging.debug(f"OR gate {node_id} clause verification passed")
    #                         or_nodes_tested += 1
    #                         tests_passed += 1
        
    #     if or_nodes_tested > 0:
    #         logging.info(f"Tested {or_nodes_tested} OR gates, all verified")
        
    #     output_nodes_tested = 0
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'output' and node['id'] != 'flag' and 'inputs' in node and node['inputs']:
    #             node_id = node['id']
    #             output_var = self.variable_map.get(node_id)
    #             input_id = node['inputs'][0]
    #             input_var = self.variable_map.get(input_id)
                
    #             if output_var and input_var:
    #                 expected_clauses = [
    #                     [-input_var, output_var],
    #                     [input_var, -output_var]
    #                 ]
                    
    #                 all_found = True
    #                 for clause in expected_clauses:
    #                     if clause not in self.cnf.clauses:
    #                         logging.error(f"Output node {node_id} missing clause: {clause}")
    #                         all_found = False
    #                         tests_failed += 1
                    
    #                 if all_found:
    #                     logging.debug(f"Output node {node_id} clause verification passed")
    #                     output_nodes_tested += 1
    #                     tests_passed += 1
        
    #     if output_nodes_tested > 0:
    #         logging.info(f"Tested {output_nodes_tested} output nodes, all verified")
        
    #     flag_node = None
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'output' and node['id'] == 'flag':
    #             flag_node = node
    #             break
        
    #     if flag_node and 'inputs' in flag_node:
    #         flag_var = self.variable_map.get('flag')
    #         flag_logic_var = self.variable_map.get(flag_node['inputs'][0])
    #         flag_logic_faulty = None
            
    #         for node_id, faulty_var in self.faulty_outputs.items():
    #             if node_id == f"{flag_node['inputs'][0]}_faulty":
    #                 flag_logic_faulty = faulty_var
    #                 break
            
    #         if flag_var and flag_logic_var:
    #             expected_clauses = [
    #                 [-flag_logic_var, flag_var],
    #                 [flag_logic_var, -flag_var]
    #             ]
                
    #             all_found = True
    #             for clause in expected_clauses:
    #                 if clause not in self.cnf.clauses:
    #                     logging.error(f"Flag node missing normal logic clause: {clause}")
    #                     all_found = False
    #                     tests_failed += 1
                
    #             if all_found:
    #                 logging.info(f"Flag node normal logic verification passed")
    #                 tests_passed += 1
            
    #         if flag_logic_faulty:
    #             expected_clause = [-flag_logic_faulty]
    #             if expected_clause in self.cnf.clauses:
    #                 logging.info(f"flag_logic_faulty == 0 constraint verification passed")
    #                 tests_passed += 1
    #             else:
    #                 logging.error(f"Missing flag_logic_faulty == 0 constraint")
    #                 tests_failed += 1
        
    #     reg_node = None
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'reg' and 'inputs' in node and not node.get('vulnerable', False):
    #             reg_node = node
    #             break
        
    #     if reg_node:
    #         node_id = reg_node['id']
    #         output_var = self.variable_map.get(node_id)
    #         input_id = reg_node['inputs'][0]
    #         input_var = self.variable_map.get(input_id)
            
    #         if output_var and input_var:
    #             expected_clauses = [
    #                 [-input_var, output_var],
    #                 [input_var, -output_var]
    #             ]
                
    #             all_found = True
    #             for clause in expected_clauses:
    #                 if clause not in self.cnf.clauses:
    #                     logging.error(f"Register {node_id} missing normal logic clause: {clause}")
    #                     all_found = False
    #                     tests_failed += 1
                
    #             if all_found:
    #                 logging.info(f"Register {node_id} normal logic verification passed")
    #                 tests_passed += 1
                
    #             faulty_input = self.faulty_outputs.get(f"{input_id}_faulty")
    #             faulty_output = self.faulty_outputs.get(f"{node_id}_faulty")
                
    #             if faulty_input and faulty_output:
    #                 expected_clauses = [
    #                     [-faulty_input, faulty_output],
    #                     [faulty_input, -faulty_output]
    #                 ]
                    
    #                 all_found = True
    #                 for clause in expected_clauses:
    #                     if clause not in self.cnf.clauses:
    #                         logging.error(f"Register {node_id} missing fault transmission clause: {clause}")
    #                         all_found = False
    #                         tests_failed += 1
                    
    #                 if all_found:
    #                     logging.info(f"Register {node_id} fault transmission logic verification passed")
    #                     tests_passed += 1
        
    #     xor_to_reg_to_output = []
        
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'output' and node['id'] != 'flag' and 'inputs' in node:
    #             output_id = node['id']
    #             reg_id = node['inputs'][0] if node['inputs'] else None
                
    #             if reg_id:
    #                 xor_id = None
    #                 for reg_node in self.circuit['nodes']:
    #                     if reg_node['id'] == reg_id and 'inputs' in reg_node:
    #                         xor_id = reg_node['inputs'][0] if reg_node['inputs'] else None
    #                         break
                    
    #                 if xor_id:
    #                     xor_faulty = self.faulty_outputs.get(f"{xor_id}_faulty")
    #                     reg_faulty = self.faulty_outputs.get(f"{reg_id}_faulty")
                        
    #                     if xor_faulty and reg_faulty:
    #                         xor_to_reg_to_output.append((xor_id, reg_id, output_id))
        
    #     if xor_to_reg_to_output:
    #         xor_id, reg_id, output_id = xor_to_reg_to_output[0]
    #         xor_faulty = self.faulty_outputs.get(f"{xor_id}_faulty")
    #         reg_faulty = self.faulty_outputs.get(f"{reg_id}_faulty")
            
    #         expected_clauses = [
    #             [-xor_faulty, reg_faulty],
    #             [xor_faulty, -reg_faulty]
    #         ]
            
    #         all_found = True
    #         for clause in expected_clauses:
    #             if clause not in self.cnf.clauses:
    #                 logging.error(f"Fault transmission path {xor_id}_faulty -> {reg_id}_faulty missing clause: {clause}")
    #                 all_found = False
    #                 tests_failed += 1
            
    #         if all_found:
    #             logging.info(f"Fault transmission path {xor_id}_faulty -> {reg_id}_faulty -> {output_id} verified")
    #             tests_passed += 1
        
    #     cmp_to_flag_logic = []
        
    #     paths = {}
    #     for node in self.circuit['nodes']:
    #         if node['type'] == 'or' and 'inputs' in node and node['inputs']:
    #             node_id = node['id']
    #             for input_id in node['inputs']:
    #                 if input_id not in paths:
    #                     paths[input_id] = []
    #                 paths[input_id].append(node_id)
        
    #     cmp_nodes = [node['id'] for node in self.circuit['nodes'] if node['id'].startswith('cmp')]
    #     for cmp_id in cmp_nodes:
    #         visited = set()
    #         queue = [(cmp_id, [cmp_id])]
            
    #         while queue:
    #             current, path = queue.pop(0)
    #             if current == 'flag_logic':
    #                 cmp_to_flag_logic.append(path)
    #                 break
                
    #             if current in visited:
    #                 continue
                
    #             visited.add(current)
                
    #             if current in paths:
    #                 for next_node in paths[current]:
    #                     if next_node not in visited:
    #                         new_path = path + [next_node]
    #                         queue.append((next_node, new_path))
        
    #     if cmp_to_flag_logic:
    #         path = cmp_to_flag_logic[0]
            
    #         for i in range(len(path) - 1):
    #             current_id = path[i]
    #             next_id = path[i + 1]
                
    #             current_var = self.variable_map.get(current_id)
    #             next_var = self.variable_map.get(next_id)
                
    #             if current_var and next_var:
    #                 expected_clause = [-current_var, next_var]
                    
    #                 if expected_clause in self.cnf.clauses:
    #                     logging.debug(f"Fault transmission {current_id} -> {next_id} clause verification passed")
    #                 else:
    #                     logging.error(f"Fault transmission {current_id} -> {next_id} missing clause: {expected_clause}")
    #                     tests_failed += 1
            
    #         logging.info(f"Comparison gate to flag_logic fault transmission path {' -> '.join(path)} verified")
    #         tests_passed += 1
        
    #     fault_model = self.circuit['fault_model']
    #     n_e = fault_model['n_e']
        
    #     if n_e == 1:
    #         control_vars = sorted(list(self.control_vars.values()))
    #         neg_control_vars = [-var for var in control_vars]
            
    #         if neg_control_vars in self.cnf.clauses:
    #             logging.info(f"Fault quantity constraint (n_e=1) verified, containing all {len(control_vars)} control variables")
    #             tests_passed += 1
    #         else:
    #             found = False
    #             for clause in self.cnf.clauses:
    #                 if all([-var in clause for var in control_vars]):
    #                     found = True
    #                     break
                
    #             if found:
    #                 logging.info(f"Fault quantity constraint (n_e=1) verified, control variables contained in other form")
    #                 tests_passed += 1
    #             else:
    #                 logging.error(f"Missing complete fault quantity constraint (n_e=1), expected to contain all control variables: {neg_control_vars}")
    #                 tests_failed += 1
        
    #     total_tests = tests_passed + tests_failed
    #     logging.info(f"CNF consistency verification completed: Total {total_tests} tests, Passed {tests_passed}, Failed {tests_failed}")
        
    #     return tests_passed, tests_failed

    def encode(self, n_e=None):
    
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
        
        if len(self.select_vars) > 0:
            logging.info(f"  - Select variables: {len(self.select_vars)}, ID range: {self.var_ranges['selects']['min']}-{self.var_ranges['selects']['max']}")
        else:
            logging.info(f"  - Select variables: {len(self.select_vars)}")
        
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
        
        # self.test_cnf()
        
        self._save_variable_map()
        
        return self.cnf
    
    def _save_variable_map(self):
        variable_map_data = {
            "variable_map": {k: v for k, v in self.variable_map.items()},
            "control_vars": {k: v for k, v in self.control_vars.items()},
            "select_vars": {k: v for k, v in self.select_vars.items()},
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
        
        for node_id, var in self.select_vars.items():
            var_to_node["selects"][str(var)] = node_id
        
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
        self.cnf.to_file(output_file)
        logging.info(f"CNF saved to {output_file}")
    
    def get_variable_map(self):
        return self.variable_map
    
    def get_control_vars(self):
        return self.control_vars
    
    def get_select_vars(self):
        return self.select_vars
    
    def get_faulty_outputs(self):
        return self.faulty_outputs