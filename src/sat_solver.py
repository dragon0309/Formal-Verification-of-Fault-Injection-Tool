import subprocess
import os
import time
import logging
from pysat.solvers import Minisat22

class SATSolver:
    def __init__(self, use_library=True):
        self.use_library = use_library
        logging.info(f"Initializing SAT solver, using {'PySAT library' if use_library else 'external MiniSAT'}")
    
    def solve_with_library(self, cnf):
        start_time = time.time()
        logging.info("Starting solving with PySAT")
        
        solver = Minisat22()
        solver.append_formula(cnf)
        is_sat = solver.solve()
        
        end_time = time.time()
        if is_sat:
            model = solver.get_model()
            logging.info(f"Solving result: SAT, time taken: {end_time - start_time:.2f} seconds")
        else:
            model = None
            logging.info(f"Solving result: UNSAT, time taken: {end_time - start_time:.2f} seconds")
        
        return is_sat, model
    
    def solve_with_minisat(self, cnf_file, output_file):
        start_time = time.time()
        logging.info(f"Starting solving with external MiniSAT, CNF file: {cnf_file}")
        
        try:
            subprocess.run(['minisat', cnf_file, output_file], check=True)
            
            with open(output_file, 'r') as f:
                result = f.readline().strip()
                if result == 'SAT':
                    model = [int(x) for x in f.readline().strip().split()[:-1]]
                    is_sat = True
                    logging.info("Solving result: SAT")
                else:
                    model = None
                    is_sat = False
                    logging.info("Solving result: UNSAT")
            
            end_time = time.time()
            logging.info(f"Solving completed, time taken: {end_time - start_time:.2f} seconds")
            return is_sat, model
            
        except subprocess.CalledProcessError:
            logging.error("MiniSAT execution failed")
            return False, None
        except FileNotFoundError:
            logging.error("MiniSAT executable not found")
            return False, None
        except Exception as e:
            logging.error(f"Error during solving process: {str(e)}")
            return False, None
        finally:
            # Clean up temporary output files
            try:
                if os.path.exists(output_file):
                    logging.debug(f"Cleaning temporary output file: {output_file}")
                    # Not deleting output file, keeping for inspection
                    # os.remove(output_file)
            except Exception as e:
                logging.warning(f"Error while cleaning temporary files: {str(e)}")
    
    def solve(self, cnf, cnf_file=None, output_file=None):
        if self.use_library:
            return self.solve_with_library(cnf)
        else:
            if cnf_file is None or output_file is None:
                raise ValueError("cnf_file and output_file must be provided when using external solver")
            return self.solve_with_minisat(cnf_file, output_file)
    
    def interpret_result(self, sat, model, variable_map, control_vars, countermeasure="detection"):
        """Interpret solving results
        
        Args:
            sat (bool): Whether satisfiable
            model (list): Model (if satisfiable)
            variable_map (dict): Variable mapping
            control_vars (dict): Control variable mapping
            countermeasure (str): Countermeasure type
            
        Returns:
            tuple: (is_fault_resistant, fault_vector)
        """
        logging.info(f"Interpreting solving results, countermeasure type: {countermeasure}")
        
        # Check if model is None
        if model is None:
            if not sat:
                logging.info("Result: Circuit is fault resistant (UNSAT)")
                return True, []
            else:
                logging.warning("Solving result is SAT but model is None, this might be an error")
                return False, []
        
        # Interpret results based on countermeasure type
        if countermeasure == "detection":
            # Detection type: if SAT, circuit has vulnerability
            if sat:
                # Find activated fault control variables
                fault_vector = []
                for node_id, var in control_vars.items():
                    # Ensure variable is within model range
                    var_index = abs(var) - 1
                    if var_index < len(model) and model[var_index] > 0:
                        fault_vector.append(node_id)
                
                logging.info(f"Result: Circuit has vulnerability, fault vector: {fault_vector}")
                return False, fault_vector
            else:
                logging.info("Result: Circuit is fault resistant (UNSAT)")
                return True, []
        
        elif countermeasure == "correction":
            # Correction type: if SAT, circuit has vulnerability
            if sat:
                # Find activated fault control variables
                fault_vector = []
                for node_id, var in control_vars.items():
                    # Ensure variable is within model range
                    var_index = abs(var) - 1
                    if var_index < len(model) and model[var_index] > 0:
                        fault_vector.append(node_id)
                
                logging.info(f"Result: Circuit has vulnerability (correction failed), fault vector: {fault_vector}")
                return False, fault_vector
            else:
                logging.info("Result: Circuit is fault resistant (correction successful)")
                return True, []
        
        else:
            logging.warning(f"Unknown countermeasure type: {countermeasure}")
            return None, [] 