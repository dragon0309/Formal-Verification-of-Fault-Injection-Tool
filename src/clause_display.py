import os
import sys
import json
import logging
import re
import argparse
import io
from typing import Dict, List, Tuple, Set, Optional, Any
from contextlib import redirect_stdout


# Setup logging
def setup_logging():
    # Configure logger
    logger = logging.getLogger('clause_display')
    logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger


# Main function
def display_categorized_clauses(cnf_file: str, var_map_file: str) -> None:
    # Setup logging
    logger = setup_logging()
    
    try:
        # Extract circuit name from filename
        circuit_name = os.path.splitext(os.path.basename(cnf_file))[0]
        logger.info(f"Processing circuit: {circuit_name}")
        
        # Load variable mapping
        logger.info(f"Loading variable mapping file: {var_map_file}")
        var_map = load_variable_map(var_map_file)
        
        # Parse CNF file
        logger.info(f"Parsing CNF file: {cnf_file}")
        header, clauses = parse_cnf_file(cnf_file)
        
        # Group clauses by pattern
        logger.info("Grouping clauses by pattern")
        grouped_clauses = group_clauses_by_pattern(clauses, var_map)
        
        # Display grouped clauses
        logger.info("Generating categorized clause display")
        display_clauses(circuit_name, header, grouped_clauses, var_map)
        
        logger.info("Done")
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        raise
    except ValueError as e:
        logger.error(f"Processing error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise


def load_variable_map(var_map_file: str) -> Dict:
    try:
        with open(var_map_file, 'r') as f:
            var_map = json.load(f)
        return var_map
    except FileNotFoundError:
        raise FileNotFoundError(f"Variable mapping file not found: {var_map_file}")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid variable mapping file format: {var_map_file}")


def parse_cnf_file(cnf_file: str) -> Tuple[str, List[List[int]]]:
  
    try:
        with open(cnf_file, 'r') as f:
            lines = f.readlines()
        
        header = ""
        clauses = []
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines and comment lines
            if not line or line.startswith('c'):
                continue
            
            # Parse header line
            if line.startswith('p cnf'):
                header = line
                continue
            
            # Parse clause line
            clause = [int(x) for x in line.split() if x != '0']
            if clause:  # Ensure clause is not empty
                clauses.append(clause)
        
        if not header:
            raise ValueError(f"CNF file missing header: {cnf_file}")
        
        return header, clauses
    
    except FileNotFoundError:
        raise FileNotFoundError(f"CNF file not found: {cnf_file}")
    except ValueError as e:
        if str(e).startswith("CNF file missing header"):
            raise
        raise ValueError(f"Invalid CNF file format: {cnf_file}")


def group_clauses_by_pattern(clauses: List[List[int]], var_map: Dict) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """
    Group clauses by logical pattern based on variable mapping and clause structure.
    
    Args:
        clauses: List of clauses
        var_map: Variable mapping dictionary
    
    Returns:
        Dict[str, Dict[str, Dict[str, Any]]]: Clauses grouped by pattern type and node
    """
    # Initialize grouping dictionary
    grouped = {
        "XOR": {},           # XOR logic clauses
        "Fault_Injection": {},  # Fault injection clauses
        "Comparison": {},    # Comparison clauses
        "OR": {},            # OR gate clauses
        "Register": {},      # Register clauses
        "Output": {},        # Output clauses
        "Countermeasure": {},  # Countermeasure clauses
        "Fault_Constraint": {},  # Fault constraint clauses
        "AtMost": {},        # AtMost constraint clauses
        "Unknown": {}        # Unclassified clauses
    }
    
    # Get variable mappings
    var_to_node = var_map["var_to_node"]
    node_var_nums = {int(k): v for k, v in var_to_node["nodes"].items()}
    control_var_nums = {int(k): v for k, v in var_to_node["controls"].items()}
    faulty_output_nums = {int(k): v for k, v in var_to_node["faulty_outputs"].items()}
    
    # 預先定義的 atmost_clauses 模式
    atmost_patterns = [
        [-4, 40], [-40, 41], [-9, -40], [-9, 41], [-41, 42], [-14, -41], 
        [-14, 42], [-42, 43], [-19, -42], [-19, 43], [-43, 44], 
        [-24, -43], [-24, 44], [-44, 45], [-29, -44], [-29, 45], 
        [-45, 46], [-34, -45], [-34, 46], [-39, -46]
    ]
    
    # Group clauses by variables involved
    clause_groups = {}
    for clause in clauses:
        # Sort variables by absolute value for consistent grouping
        key = tuple(sorted([abs(v) for v in clause]))
        if key not in clause_groups:
            clause_groups[key] = []
        clause_groups[key].append(clause)
    
    # 收集所有變量，用於後續識別 OR 邏輯和 atmost 約束
    all_vars = set()
    for clause in clauses:
        for var in clause:
            all_vars.add(abs(var))
    
    # 預先收集所有 AtMost 約束子句
    atmost_clauses = []
    for clause in clauses:
        # 檢查子句是否符合 AtMost 約束模式
        if len(clause) == 2:
            clause_set = set(clause)
            for pattern in atmost_patterns:
                if set(pattern) == clause_set:
                    atmost_clauses.append(clause)
                    break
    
    if atmost_clauses:
        group_id = "atmost_constraints"
        explanation = "Fault number constraints (AtMost)"
        
        if group_id not in grouped["AtMost"]:
            grouped["AtMost"][group_id] = {
                "explanation": explanation,
                "clauses": []
            }
        grouped["AtMost"][group_id]["clauses"].extend(atmost_clauses)
        
        # 從 clause_groups 中移除已處理的子句
        for clause in atmost_clauses:
            key = tuple(sorted([abs(v) for v in clause]))
            if key in clause_groups and clause in clause_groups[key]:
                clause_groups[key].remove(clause)
    
    # 查找可能的 OR 邏輯組
    or_groups = {}
    for key, group in clause_groups.items():
        # OR 邏輯通常有 3 個子句：[-in1, output], [-in2, output], [in1, in2, -output]
        if len(key) == 2 and len(group) == 2:
            # 可能是 OR 邏輯的前兩個子句
            var1, var2 = key
            # 檢查這兩個子句是否形如 [-in1, output], [-in2, output]
            if all(len(c) == 2 for c in group):
                # 找出共同的輸出變量
                common_vars = set(abs(v) for c in group for v in c)
                if len(common_vars) == 2:
                    # 查找可能的第三個子句
                    for other_key, other_group in clause_groups.items():
                        if len(other_key) == 3 and len(other_group) == 1 and var1 in other_key and var2 in other_key:
                            third_var = next(v for v in other_key if v != var1 and v != var2)
                            if third_var in common_vars:
                                # 找到可能的 OR 邏輯組
                                or_group_key = (var1, var2, third_var)
                                if or_group_key not in or_groups:
                                    or_groups[or_group_key] = []
                                or_groups[or_group_key].extend(group)
                                or_groups[or_group_key].extend(other_group)
    
    # 將 OR 邏輯組添加到分組中
    for or_key, or_clauses in or_groups.items():
        var1, var2, output_var = or_key
        
        # 獲取變量名稱
        var1_name = ""
        var2_name = ""
        output_name = ""
        
        if var1 in node_var_nums:
            var1_name = node_var_nums[var1]
        elif var1 in control_var_nums:
            var1_name = f"control_{control_var_nums[var1]}"
        elif var1 in faulty_output_nums:
            var1_name = faulty_output_nums[var1]
        else:
            var1_name = f"var_{var1}"
        
        if var2 in node_var_nums:
            var2_name = node_var_nums[var2]
        elif var2 in control_var_nums:
            var2_name = f"control_{control_var_nums[var2]}"
        elif var2 in faulty_output_nums:
            var2_name = faulty_output_nums[var2]
        else:
            var2_name = f"var_{var2}"
        
        if output_var in node_var_nums:
            output_name = node_var_nums[output_var]
        elif output_var in control_var_nums:
            output_name = f"control_{control_var_nums[output_var]}"
        elif output_var in faulty_output_nums:
            output_name = faulty_output_nums[output_var]
        else:
            output_name = f"var_{output_var}"
        
        # 檢查是否符合 OR 邏輯模式
        expected_clauses = [
            [-var1, output_var],
            [-var2, output_var],
            [var1, var2, -output_var]
        ]
        
        or_pattern = True
        for expected in expected_clauses:
            if not any(set(expected) == set(clause) for clause in or_clauses):
                or_pattern = False
                break
        
        if or_pattern:
            group_id = output_name
            explanation = f"{var1_name} OR {var2_name} = {output_name} (OR Gate)"
            
            if group_id not in grouped["OR"]:
                grouped["OR"][group_id] = {
                    "explanation": explanation,
                    "clauses": []
                }
            grouped["OR"][group_id]["clauses"].extend(or_clauses)
            
            # 從 clause_groups 中移除已處理的子句
            for clause in or_clauses:
                key = tuple(sorted([abs(v) for v in clause]))
                if key in clause_groups and clause in clause_groups[key]:
                    clause_groups[key].remove(clause)
    
    # Process each group of clauses
    for var_key, group_clauses in clause_groups.items():
        # Skip empty groups
        if not group_clauses:
            continue
        
        # Check for fault constraint
        control_vars_in_group = [v for v in var_key if v in control_var_nums]
        if control_vars_in_group:
            if len(control_vars_in_group) > 2:
                # At least 1 fault constraint (multiple control variables)
                group_id = "at_least_one_control"
                explanation = "At least 1 fault constraint"
                if group_id not in grouped["Fault_Constraint"]:
                    grouped["Fault_Constraint"][group_id] = {
                        "explanation": explanation,
                        "clauses": []
                    }
                grouped["Fault_Constraint"][group_id]["clauses"].extend(group_clauses)
                continue
            elif len(control_vars_in_group) == 2 and len(var_key) == 2:
                # At most 1 fault constraint (pairwise encoding)
                group_id = "at_most_one_control"
                explanation = "At most 1 fault constraint"
                if group_id not in grouped["Fault_Constraint"]:
                    grouped["Fault_Constraint"][group_id] = {
                        "explanation": explanation,
                        "clauses": []
                    }
                grouped["Fault_Constraint"][group_id]["clauses"].extend(group_clauses)
                continue

        
        # Check for countermeasure constraint (contains flag variable)
        if 80 in var_key:  # flag variable
            group_id = "flag"
            if group_id not in grouped["Countermeasure"]:
                grouped["Countermeasure"][group_id] = {
                    "explanation": "Detection: flag = 0",
                    "clauses": []
                }
            grouped["Countermeasure"][group_id]["clauses"].extend(group_clauses)
            continue
        
        # Check for XOR pattern (4 clauses with 3 variables)
        if len(group_clauses) == 4 and len(var_key) == 3:
            # Try to identify input and output variables
            var_names = {}
            for var in var_key:
                if var in node_var_nums:
                    var_names[var] = node_var_nums[var]
                elif var in control_var_nums:
                    var_names[var] = f"control_{control_var_nums[var]}"
                elif var in faulty_output_nums:
                    var_names[var] = faulty_output_nums[var]
                else:
                    var_names[var] = f"var_{var}"
            
            # Check for XOR gate pattern
            output_candidates = [(var, name) for var, name in var_names.items() 
                               if name.startswith('z') and len(name) == 2]
            input_candidates = [(var, name) for var, name in var_names.items() 
                              if name.startswith('d') or name.startswith('k')]
            
            if output_candidates and len(input_candidates) == 2:
                output_var, output_name = output_candidates[0]
                group_id = output_name
                explanation = f"{input_candidates[0][1]} XOR {input_candidates[1][1]} = {output_name}"
                
                if group_id not in grouped["XOR"]:
                    grouped["XOR"][group_id] = {
                        "explanation": explanation,
                        "clauses": []
                    }
                grouped["XOR"][group_id]["clauses"].extend(group_clauses)
                continue
            
            # Check for redundant XOR pattern
            redundant_candidates = [(var, name) for var, name in var_names.items() 
                                  if name.endswith('_red')]
            if redundant_candidates and len(input_candidates) >= 2:
                redundant_var, redundant_name = redundant_candidates[0]
                group_id = redundant_name
                base_name = redundant_name.split('_')[0]
                explanation = f"{input_candidates[0][1]} XOR {input_candidates[1][1]} = {redundant_name} (Redundant)"
                
                if group_id not in grouped["XOR"]:
                    grouped["XOR"][group_id] = {
                        "explanation": explanation,
                        "clauses": []
                    }
                grouped["XOR"][group_id]["clauses"].extend(group_clauses)
                continue
            
            # Check for fault injection pattern (bit-flip)
            control_vars = [(var, name) for var, name in var_names.items() if var in control_var_nums]
            normal_vars = [(var, name) for var, name in var_names.items() 
                         if var in node_var_nums and not name.endswith('_red')]
            faulty_outputs = [(var, name) for var, name in var_names.items() if var in faulty_output_nums]
            
            if control_vars and normal_vars and faulty_outputs:
                control_var, control_name = control_vars[0]
                normal_var, normal_name = normal_vars[0]
                faulty_var, faulty_name = faulty_outputs[0]
                
                # Check if clauses match bit-flip pattern
                bit_flip_pattern = True
                expected_clauses = [
                    [control_var, normal_var, -faulty_var],
                    [control_var, -normal_var, faulty_var],
                    [-control_var, normal_var, faulty_var],
                    [-control_var, -normal_var, -faulty_var]
                ]
                
                for expected in expected_clauses:
                    if not any(set(expected) == set(clause) for clause in group_clauses):
                        bit_flip_pattern = False
                        break
                
                if bit_flip_pattern:
                    node_name = normal_name
                    group_id = node_name
                    explanation = f"Bit-flip fault on {node_name}: {control_name} {node_name} {faulty_name}"
                    
                    if group_id not in grouped["Fault_Injection"]:
                        grouped["Fault_Injection"][group_id] = {
                            "explanation": explanation,
                            "clauses": []
                        }
                    grouped["Fault_Injection"][group_id]["clauses"].extend(group_clauses)
                    continue
            
            # Check for comparison XOR pattern (z0_faulty XOR z0_red = cmp0)
            faulty_vars = [(var, name) for var, name in var_names.items() if name.endswith('_faulty')]
            redundant_vars = [(var, name) for var, name in var_names.items() if name.endswith('_red')]
            comparison_vars = [(var, name) for var, name in var_names.items() if name.startswith('cmp')]
            
            if faulty_vars and redundant_vars and comparison_vars:
                faulty_var, faulty_name = faulty_vars[0]
                redundant_var, redundant_name = redundant_vars[0]
                comparison_var, comparison_name = comparison_vars[0]
                
                group_id = comparison_name
                explanation = f"{faulty_name} XOR {redundant_name} = {comparison_name} (Fault Detection)"
                
                if group_id not in grouped["Comparison"]:
                    grouped["Comparison"][group_id] = {
                        "explanation": explanation,
                        "clauses": []
                    }
                grouped["Comparison"][group_id]["clauses"].extend(group_clauses)
                continue
        
        # Check for register logic pattern (2 clauses with 2 variables)
        if len(group_clauses) == 2 and len(var_key) == 2:
            # Check if one is a register and one is another node
            register_vars = [v for v in var_key if 41 <= v <= 48 and v in node_var_nums]
            other_vars = [v for v in var_key if v not in register_vars]
            
            if register_vars and other_vars:
                register_var = register_vars[0]
                register_name = node_var_nums[register_var]
                
                other_var = other_vars[0]
                if other_var in node_var_nums:
                    other_name = node_var_nums[other_var]
                elif other_var in faulty_output_nums:
                    other_name = faulty_output_nums[other_var]
                else:
                    other_name = f"var_{other_var}"
                
                group_id = register_name
                explanation = f"{other_name} = {register_name} (Register Connection)"
                
                if group_id not in grouped["Register"]:
                    grouped["Register"][group_id] = {
                        "explanation": explanation,
                        "clauses": []
                    }
                grouped["Register"][group_id]["clauses"].extend(group_clauses)
                continue
        
        # Check for simple OR patterns (2 variables in 1 clause)
        if len(group_clauses) == 1 and len(var_key) == 2:
            # Check if it's a simple OR pattern
            clause = group_clauses[0]
            if len(clause) == 2:  # 簡單的 OR 子句應該有 2 個變量
                var1, var2 = abs(clause[0]), abs(clause[1])
                var1_neg = clause[0] < 0
                var2_neg = clause[1] < 0
                
                # 獲取變量名稱
                var1_name = ""
                var2_name = ""
                
                if var1 in node_var_nums:
                    var1_name = node_var_nums[var1]
                elif var1 in control_var_nums:
                    var1_name = f"control_{control_var_nums[var1]}"
                elif var1 in faulty_output_nums:
                    var1_name = faulty_output_nums[var1]
                else:
                    var1_name = f"var_{var1}"
                
                if var2 in node_var_nums:
                    var2_name = node_var_nums[var2]
                elif var2 in control_var_nums:
                    var2_name = f"control_{control_var_nums[var2]}"
                elif var2 in faulty_output_nums:
                    var2_name = faulty_output_nums[var2]
                else:
                    var2_name = f"var_{var2}"
                
                
        
        # Check for complex OR patterns (1 clause with 3 variables)
        if len(group_clauses) == 1 and len(var_key) == 3:
            clause = group_clauses[0]
            if len(clause) == 3:  # 三變量 OR 子句
                # 獲取變量名稱
                var_names = []
                var_signs = []
                or_gate_var = None
                
                for var in clause:
                    var_num = abs(var)
                    var_neg = var < 0
                    var_signs.append(var_neg)
                    
                    if var_num in node_var_nums:
                        var_name = node_var_nums[var_num]
                        # 檢查是否為 OR 門輸出
                        if 73 <= var_num <= 79 or var_name.startswith('or') or var_name == 'flag_logic':
                            or_gate_var = (var_num, var_name, var_neg)
                        var_names.append((var_num, var_name))
                    elif var_num in control_var_nums:
                        var_name = f"control_{control_var_nums[var_num]}"
                        var_names.append((var_num, var_name))
                    elif var_num in faulty_output_nums:
                        var_name = faulty_output_nums[var_num]
                        var_names.append((var_num, var_name))
                    else:
                        var_name = f"var_{var_num}"
                        var_names.append((var_num, var_name))
                
                # 檢查是否為 OR 門邏輯（兩個輸入，一個輸出）
                if or_gate_var and or_gate_var[2]:  # OR 門輸出為負
                    inputs = [(num, name) for num, name in var_names if num != or_gate_var[0]]
                    if len(inputs) == 2:
                        or_gate_name = or_gate_var[1]
                        input1_name = inputs[0][1]
                        input2_name = inputs[1][1]
                        
                        # 檢查是否有對應的兩個子句 [-in1, output] 和 [-in2, output]
                        in1_num = inputs[0][0]
                        in2_num = inputs[1][0]
                        out_num = or_gate_var[0]
                        
                        # 查找可能的其他兩個子句
                        found_clauses = []
                        for other_key, other_group in clause_groups.items():
                            if len(other_key) == 2 and len(other_group) > 0:
                                if (in1_num in other_key and out_num in other_key) or (in2_num in other_key and out_num in other_key):
                                    for other_clause in other_group:
                                        if (set(other_clause) == set([-in1_num, out_num]) or 
                                            set(other_clause) == set([-in2_num, out_num])):
                                            found_clauses.append(other_clause)
                        
                        # 如果找到了對應的子句，則將這三個子句組合為 OR 邏輯
                        if len(found_clauses) == 2:
                            group_id = f"or_gate_{or_gate_var[0]}"
                            explanation = f"{input1_name} OR {input2_name} = {or_gate_name} (OR Gate Definition)"
                            
                            all_clauses = [clause] + found_clauses
                            
                            if group_id not in grouped["OR"]:
                                grouped["OR"][group_id] = {
                                    "explanation": explanation,
                                    "clauses": []
                                }
                            grouped["OR"][group_id]["clauses"].extend(all_clauses)
                            
                            # 從 clause_groups 中移除已處理的子句
                            for other_clause in found_clauses:
                                other_key = tuple(sorted([abs(v) for v in other_clause]))
                                if other_key in clause_groups and other_clause in clause_groups[other_key]:
                                    clause_groups[other_key].remove(other_clause)
                            
                            continue
    
    # Sort clauses within each group
    for pattern_type in grouped:
        for group_id in grouped[pattern_type]:
            # Sort clauses by first variable, then second, etc.
            grouped[pattern_type][group_id]["clauses"].sort(key=lambda c: tuple(c))
    
    return grouped


def get_human_readable_clause(
    clause: List[int], 
    node_var_nums: Dict[int, str], 
    control_var_nums: Dict[int, str], 
    faulty_output_nums: Dict[int, str]
) -> str:

    literals = []
    
    for var in clause:
        var_num = abs(var)
        negated = var < 0
        
        # Determine variable name
        if var_num in control_var_nums:
            var_name = f"control_{control_var_nums[var_num]}"
        elif var_num in faulty_output_nums:
            var_name = faulty_output_nums[var_num]
        elif var_num in node_var_nums:
            var_name = node_var_nums[var_num]
        else:
            var_name = f"var_{var_num}"
        
        # Add negation symbol
        if negated:
            literals.append(f"~{var_name}")
        else:
            literals.append(var_name)
    
    # Join literals with ∨ and wrap in parentheses
    return f"({' ∨ '.join(literals)})"


def display_clauses(
    circuit_name: str, 
    header: str, 
    grouped_clauses: Dict[str, Dict[str, Dict[str, Any]]], 
    var_map: Dict
) -> None:
    
    # Extract variable and clause counts
    match = re.search(r'p cnf (\d+) (\d+)', header)
    if not match:
        raise ValueError(f"Invalid CNF header: {header}")
    
    var_count = match.group(1)
    clause_count = match.group(2)
    
    # Print circuit info and header
    print(f"c Circuit: {circuit_name}")
    print(f"c Variable Count: {var_count}, Clause Count: {clause_count}")
    print(header)
    
    # Get variable mappings
    var_to_node = var_map["var_to_node"]
    node_var_nums = {int(k): v for k, v in var_to_node["nodes"].items()}
    control_var_nums = {int(k): v for k, v in var_to_node["controls"].items()}
    faulty_output_nums = {int(k): v for k, v in var_to_node["faulty_outputs"].items()}
    
    # Order of pattern types for display
    pattern_order = [
        "XOR", 
        "Fault_Injection", 
        "Comparison", 
        "OR", 
        "Register", 
        "Output", 
        "Countermeasure", 
        "Fault_Constraint",
        "AtMost",
        "Unknown"
    ]
    
    # Display grouped clauses
    for pattern_type in pattern_order:
        if not grouped_clauses[pattern_type]:
            continue
        
        for group_id, group_data in sorted(grouped_clauses[pattern_type].items()):
            explanation = group_data["explanation"]
            clauses = group_data["clauses"]
            
            # Print section header
            print(f"c --------------------------------------------------")
            print(f"c {pattern_type} ({group_id})")
            print(f"c Explanation: {explanation}")
            print(f"c")
            
            # Print clauses
            for clause in clauses:
                dimacs = " ".join([str(v) for v in clause]) + " 0"
                human_readable = get_human_readable_clause(clause, node_var_nums, control_var_nums, faulty_output_nums)
                print(f"{dimacs}  c {human_readable}")
            
            # Add separator after group
            print(f"c")


def save_categorized_clauses(cnf_file: str, var_map_file: str, output_file: str) -> None:

    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Capture output
    f = io.StringIO()
    with redirect_stdout(f):
        display_categorized_clauses(cnf_file, var_map_file)
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as out_file:
        out_file.write(f.getvalue())


def main():
    # Create command line argument parser
    parser = argparse.ArgumentParser(
        description='Parse CNF file and variable mapping JSON file, display clauses in categorized format.'
    )
    
    # Add command line arguments
    parser.add_argument('cnf_file', help='Path to the CNF file')
    parser.add_argument('var_map_file', help='Path to the variable mapping JSON file')
    parser.add_argument('-o', '--output', help='Path to the output file (if not specified, output to standard output)')
    
    # Parse command line arguments
    args = parser.parse_args()
    
    # Check if files exist
    if not os.path.isfile(args.cnf_file):
        print(f"Error: CNF file not found: {args.cnf_file}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.isfile(args.var_map_file):
        print(f"Error: Variable mapping file not found: {args.var_map_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # If output file specified, save to file, otherwise output to standard output
        if args.output:
            save_categorized_clauses(args.cnf_file, args.var_map_file, args.output)
            print(f"Categorized clauses saved to: {args.output}")
        else:
            display_categorized_clauses(args.cnf_file, args.var_map_file)
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main() 