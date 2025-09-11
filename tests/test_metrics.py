import sys
import os
# Add the src directory to the import path so that the modules package can be
# imported when running the tests directly from the repository root.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

import modules.calculate_metrics as calculate_metrics
import modules.metrics.project_metrics as project_metrics

def test_cyclomatic_complexity():
    """
    Test the cyclomatic complexity metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "cyclomatic_complexity.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_cyclomatic_complexity)
    trueRestult = [2, 2, 3, 4, 3, 4, 4, 4, 8]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueRestult[i], f"Expected {trueRestult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_number_of_loops():
    """
    Test the number of loops metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_loops.cpp")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_loops)
    trueResult = [0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        
def test_number_nested_loops():
    """
    Test the number of nested loops metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_nested_loops.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_nested_loops)
    trueResult = [0, 0, 1, 1, 1, 1, 1, 3, 2]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        
def test_max_loop_nesting_level():
    """
    Test the maximum loop nesting level metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "max_loop_nesting_level.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_max_nesting_loop_depth)
    trueResult = [0, 1, 2, 3, 3, 2, 2, 3, 13]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_number_of_parameter_variables():
    """
    Test the number of parameter variables metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_parameter_variables.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_parameter_variables)
    trueResult = [0, 1, 2, 3, 4]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        
def test_number_of_variables_as_callee_parameters():
    """
    Test the number of variables as callee parameters metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_variables_as_callee_parameters.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_callee_parameter_variables)
    trueResult = [0, 1, 2, 0, 0, 1, 2, 1, 4, 2, 5, 1]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_number_of_pointer_arithmetic_ops():
    """
    Test the number of pointer arithmetic operations metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_pointer_arithmetic_operations.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_pointer_arithmetic)
    print(*[t[1] for t in testResult])  
    trueResult = [3, 2, 2, 2, 2, 0, 1, 1, 2, 2]

    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_number_of_variables_involved_in_pointer_arithmetic():
    """
    Test the number of variables involved in pointer arithmetic metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_variables_involved_in_pointer_arithmetic.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_variables_involved_in_pointer_arithmetic)
    print(*[t[1] for t in testResult])  
    trueResult = [1, 2, 3, 1, 2, 3, 2, 1, 1, 1, 3]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_max_pointer_arithmetic_variables_is_involved_in():
    """
    Test the maximum pointer arithmetic variables involved in metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "max_pointer_arithmetic_variable_is_involved.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_max_pointer_arithmetic_variable_is_involved_in)
    trueResult = [1, 2, 1, 1, 2, 1, 2, 2, 3]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_calculate_number_of_nested_control_structures():
    """
    Test the number of nested control structures metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "controll_structures.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_nested_control_structures)
    trueResult = [0, 0, 0, 0, 0, 0, 1, 1, 2]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_calculate_maximum_nesting_level_of_control_structures():
    """
    Test the maximum nesting level of control structures metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "controll_structures.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_maximum_nesting_level_of_control_structures)
    trueResult = [0, 1, 1, 1, 1, 1, 2, 3, 4]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_calculate_maximum_of_control_dependent_control_structures():
    """
    Test the maximum of control dependent control structures metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "control_dependent_control_structures.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_maximum_of_control_dependent_control_structures)
    trueResult = [0, 1, 2, 4, 5, 9, 3]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_calculate_maximum_of_data_dependent_control_structures():
    """
    Test the maximum of data dependent control structures metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "data_dependent_control_structures.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_maximum_of_data_dependent_control_structures)
    trueResult = [0, 1, 3, 6]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_calculate_number_if_structures_without_else():
    """
    Test the number of if structures without else metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "if_structures_without_else.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_if_structures_without_else)
    trueResult = [1, 1, 0, 2, 2, 4]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_number_of_variables_involved_in_control_predicates():
    """
    Test the number of variables involved in control predicates metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_variables_involved_in_control_predicates.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_variables_involved_in_control_predicates)
    trueResult = [1, 2, 3, 4, 3, 4, 2, 4]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"


def test_project_metrics_num_changes():
    """
    Test NumChanges (git commit count touching file) using tests/TestWorkspace repo.
    """
    file_path = os.path.join(os.getcwd(), "tests", "TestWorkspace", "TestFile.c")
    value = project_metrics.calculate_num_changes(file_path)
    assert value == 4, f"Expected 4 commits but got {value} for {file_path}"


def test_project_metrics_lines_changed():
    """
    Test LinesChanged (added + deleted) using tests/TestWorkspace repo.
    """
    file_path = os.path.join(os.getcwd(), "tests", "TestWorkspace", "TestFile.c")
    value = project_metrics.calculate_lines_changed(file_path)
    assert value == 17, f"Expected 17 lines changed but got {value} for {file_path}"


def test_project_metrics_lines_new():
    """
    Test LinesNew (added) using tests/TestWorkspace repo.
    """
    file_path = os.path.join(os.getcwd(), "tests", "TestWorkspace", "TestFile.c")
    value = project_metrics.calculate_lines_new(file_path)
    assert value == 13, f"Expected 13 new lines but got {value} for {file_path}"
