import os
import sys
import argparse
import logging
import json
import time
from datetime import datetime
from cnf_encoder import CNFEncoder
from sat_solver import SATSolver
from clause_display import display_categorized_clauses

def setup_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def validate_args(args):
    valid_circuits = ['lfsr', 'xor_cipher', 'sbox', 'shift_cipher', 'mixcolumn']
    if args.circuit not in valid_circuits:
        logging.error(f"Error: Invalid circuit name. Please choose from: {', '.join(valid_circuits)}")
        return False
    
    # Check n_e
    if args.n_e is not None and args.n_e <= 0:
        logging.error("Error: n_e must be a positive integer")
        return False
    
    # Check fault type
    valid_fault_types = ['bit-flip', 'set', 'reset']
    if args.fault_type is not None and args.fault_type not in valid_fault_types:
        logging.error(f"Error: Invalid fault type. Please choose from: {', '.join(valid_fault_types)}")
        return False
    
    # Check countermeasure type
    valid_countermeasures = ['detection', 'correction']
    if args.countermeasure is not None and args.countermeasure not in valid_countermeasures:
        logging.error(f"Error: Invalid countermeasure type. Please choose from: {', '.join(valid_countermeasures)}")
        return False
    
    return True

def modify_json_if_needed(json_data, args):
    modified = False
    
    # Modify n_e
    if args.n_e is not None:
        json_data['fault_model']['n_e'] = args.n_e
        modified = True
        logging.info(f"Modified JSON: n_e = {args.n_e}")
    
    # Modify fault type
    if args.fault_type is not None:
        json_data['fault_model']['fault_type'] = args.fault_type
        modified = True
        logging.info(f"Modified JSON: fault_type = {args.fault_type}")
    
    # Modify countermeasure type
    if args.countermeasure is not None:
        json_data['countermeasure'] = args.countermeasure
        modified = True
        logging.info(f"Modified JSON: countermeasure = {args.countermeasure}")
    
    return json_data, modified

def main():
    setup_logging()
    
    start_time = time.time()
    logging.info("=== Fault Injection Verification Tool ===")
    logging.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    parser = argparse.ArgumentParser(description='Verify fault injection resistance of cryptographic circuits')
    parser.add_argument('circuit', help='Circuit name (lfsr, xor_cipher, sbox, shift_cipher, mixcolumn)')
    parser.add_argument('--use-minisat', action='store_true', help='Use external MiniSAT solver')
    parser.add_argument('--n_e', type=int, help='Maximum number of faults per clock cycle (overrides JSON value)')
    parser.add_argument('--fault-type', choices=['bit-flip', 'set', 'reset'], 
                        help='Fault type (overrides JSON value)')
    parser.add_argument('--countermeasure', choices=['detection', 'correction'], 
                        help='Countermeasure type (overrides JSON value)')
    parser.add_argument('--no-categorize', action='store_true', 
                        help='Skip generating categorized clauses output')
    args = parser.parse_args()
    
    # Validate arguments
    if not validate_args(args):
        sys.exit(1)
    
    # Build file paths
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    json_file = os.path.join(base_dir, 'inputs', f'{args.circuit}.json')
    cnf_file = os.path.join(base_dir, 'outputs', f'{args.circuit}.cnf')
    var_map_file = os.path.join(base_dir, 'outputs', f'{args.circuit}_variable_map.json')
    categorized_file = os.path.join(base_dir, 'outputs', f'{args.circuit}_categorized.txt')
    output_file = os.path.join(base_dir, 'outputs', f'{args.circuit}.out')
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(cnf_file), exist_ok=True)
    
    try:
        # Read JSON
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        
        # Modify JSON based on command line arguments
        json_data, json_modified = modify_json_if_needed(json_data, args)
        
        # Get countermeasure type
        countermeasure = json_data['countermeasure']
        
        # Create CNF encoder
        encoder = CNFEncoder(json_file)
        
        # Encode circuit
        cnf = encoder.encode(args.n_e)
        
        # Save CNF file
        encoder.save_cnf(cnf_file)
        
        # Generate categorized clauses output if not disabled
        if not args.no_categorize and os.path.exists(var_map_file):
            logging.info("Generating categorized clauses output...")
            try:
                import io
                from contextlib import redirect_stdout
                
                f = io.StringIO()
                with redirect_stdout(f):
                    display_categorized_clauses(cnf_file, var_map_file)
                
                with open(categorized_file, 'w', encoding='utf-8') as out_file:
                    out_file.write(f.getvalue())
                
                logging.info(f"Categorized clauses saved to: {categorized_file}")
            except Exception as e:
                logging.error(f"Failed to generate categorized clauses: {str(e)}")
                logging.debug("Continuing with SAT solving...")
        
        # Create solver
        solver = SATSolver(use_library=not args.use_minisat)
        
        # Solve
        sat, model = solver.solve(cnf, cnf_file, output_file)
        
        # Interpret results
        is_resistant, fault_vector = solver.interpret_result(
            sat, model,
            encoder.get_variable_map(),
            encoder.get_control_vars(),
            countermeasure
        )
        
        # Output results
        if is_resistant:
            print("Circuit is fault resistant")
        else:
            print("Circuit has vulnerability")
            print("Fault vector:", fault_vector)
        
        # Log total time
        end_time = time.time()
        logging.info(f"Total time: {end_time - start_time:.2f} seconds")
        logging.info(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info("====================")
            
    except FileNotFoundError:
        logging.error(f"Error: Input file not found {json_file}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        logging.exception("Detailed error information")
        sys.exit(1)

if __name__ == '__main__':
    main() 