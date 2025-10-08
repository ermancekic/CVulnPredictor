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

def test_cyclomatic_complexity_more():
    """
    Additional cases for cyclomatic complexity covering do-while, ternary operator,
    switch fallthrough, complex boolean conditions, and mixed constructs.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "cyclomatic_complexity_more.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_cyclomatic_complexity)
    # Expected per function in file order:
    # noControl -> 1
    # doWhileOnce -> 2
    # doWhileNested -> 3
    # conditionalSimple -> 2
    # conditionalNested -> 3
    # switchFallthrough -> 3 (two case labels share a block)
    # ifComplexCond -> 2 (&& and || do not add decisions)
    # elseIfChain3 -> 4 (three if-nodes)
    # mixAll -> 8 (for + while + do + if + 2 cases + ternary)
    trueResult = [1, 2, 3, 2, 3, 3, 2, 4, 8]

    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], (
            f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        )

def test_cyclomatic_complexity_cpp():
    """
    C++-spezifische Fälle: catch-Blöcke erhöhen die Komplexität (AST-basiert).
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "cyclomatic_complexity_cpp.cpp")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_cyclomatic_complexity)
    # Expected per function in file order:
    # tryOneCatch -> 2 (one catch)
    # tryTwoCatches -> 3 (two catches)
    # tryCatchWithIf -> 3 (one catch + one if)
    trueResult = [2, 3, 3]

    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], (
            f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        )

def test_number_of_loops():
    """
    Test the number of loops metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_loops.cpp")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_loops)
    trueResult = [0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_lines_of_code():
    """
    Test the lines of code metric on a sample C source file.
    Counts distinct non-comment, non-blank lines within the function's extent.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "lines_of_code.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_loc)
    # Expected per function in file order:
    # empty, simple, with_macro, empty_block_lines, comments_and_blanks,
    # with_multiline_macro, only_semicolons
    trueResult = [1, 6, 5, 3, 4, 5, 7]

    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], (
            f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        )
        
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
    # Extended with negative cases that should yield 0 (false positives):
    # pointerAssignmentNoArith, pointerComparisonNoArith, addressOfNoArith,
    # dereferenceNoArith, arrayIndexingNoArith, pointerCastNoArith
    # Adjusted to count dereference (*p) and member access via pointer (->)
    # as pointer arithmetic per LEOPARD
    trueResult = [3, 2, 2, 2, 2, 0, 1, 1, 2, 2, 0, 0, 0, 1, 0, 0, 2, 0]

    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_number_of_variables_involved_in_pointer_arithmetic():
    """
    Test the number of variables involved in pointer arithmetic metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "number_of_variables_involved_in_pointer_arithmetic.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_number_of_variables_involved_in_pointer_arithmetic)
    print(*[t[1] for t in testResult])  
    # Expected counts per function in source order:
    # oneUnaryPointer -> 1
    # twoUnaryPointers -> 2
    # threeUnaryPointers -> 3
    # oneBinaryPointer -> 1
    # twoBinaryPointers -> 2
    # threeBinaryPointers -> 3
    # mixedUnaryBinary -> 2
    # pointerWithOffset -> 1
    # pointerCompoundAssignment -> 1
    # pointerDecrement -> 1
    # pointerDifference -> 3 (arr, ptr1, ptr2)
    # pointerAssignment_no_arith -> 0 (not arithmetic)
    # pointerCast_no_arith -> 0 (not arithmetic)
    # pointerAddressOf_no_arith -> 0 (not arithmetic)
    # pointerDereference_no_arith -> 0 (not arithmetic)
    # pointerCompare_no_arith -> 0 (not arithmetic)
    # notPointerTypes_no_arith -> 0 (not arithmetic)
    # Adjusted to count dereference (*p) and member access via pointer (->)
    # as pointer arithmetic per LEOPARD
    trueResult = [1, 2, 3, 1, 2, 3, 2, 1, 1, 1, 3, 0, 0, 0, 1, 0, 0, 1, 0]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_max_pointer_arithmetic_variables_is_involved_in():
    """
    Test the maximum pointer arithmetic variables involved in metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "max_pointer_arithmetic_variable_is_involved.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_max_pointer_arithmetic_variable_is_involved_in)
    trueResult = [1, 2, 1, 1, 2, 1, 2, 2, 2]
    
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

def test_calculate_maximum_of_control_dependent_control_structures():
    """
    Test the maximum of control dependent control structures metric on a sample C source file.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "control_dependent_control_structures.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_maximum_of_control_dependent_control_structures)
    # Extended to cover SWITCH_STMT and DO_STMT in the fixture
    trueResult = [0, 1, 2, 4, 5, 9, 3, 1, 2, 2]
    
    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"

def test_calculate_maximum_of_control_dependent_control_structures_cpp():
    """
    Cover C++ range-for (CXX_FOR_RANGE_STMT) for this metric using a minimal C++ fixture.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "control_dependent_control_structures.cpp")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_maximum_of_control_dependent_control_structures)
    trueResult = [1, 2]
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
    assert value == 5, f"Expected 5 commits but got {value} for {file_path}"


def test_project_metrics_lines_changed():
    """
    Test LinesChanged (added + deleted) using tests/TestWorkspace repo.
    """
    file_path = os.path.join(os.getcwd(), "tests", "TestWorkspace", "TestFile.c")
    value = project_metrics.calculate_lines_changed(file_path)
    assert value == 21, f"Expected 21 lines changed but got {value} for {file_path}"


def test_project_metrics_lines_new():
    """
    Test LinesNew (added) using tests/TestWorkspace repo.
    """
    file_path = os.path.join(os.getcwd(), "tests", "TestWorkspace", "TestFile.c")
    value = project_metrics.calculate_lines_new(file_path)
    assert value == 17, f"Expected 17 new lines but got {value} for {file_path}"


def test_project_metrics_num_devs():
    """
    Test NumDevs (distinct authors by email) using tests/TestWorkspace repo.
    The history of TestFile.c is authored by a single email.
    """
    file_path = os.path.join(os.getcwd(), "tests", "TestWorkspace", "TestFile.c")
    value = project_metrics.calculate_num_devs(file_path)
    assert value == 2, f"Expected 2 developer but got {value} for {file_path}"


def test_maximum_nesting_level_of_control_structures():
    """
    Test the maximum nesting level of control structures on crafted C examples.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "maximum_nesting_level_of_control_structures.c")
    testResult = calculate_metrics.run_test(sourceCode, calculate_metrics.calculate_maximum_nesting_level_of_control_structures)

    # Expected per function in source order:
    # no_control -> 0
    # one_if -> 1
    # nested_if -> 2
    # if_in_loop -> 3  (for -> if -> while)
    # switch_with_if -> 2  (switch -> if)
    # else_if_chain -> 1  (else-if chain flattened; same nesting level)
    # loop_switch_if_nested -> 3  (for -> switch -> if)
    # triple_nested_loops_with_if -> 4  (for -> while -> do -> if)
    # nested_else_if 
    trueResult = [0, 1, 2, 3, 2, 1, 3, 4, 3]

    for i in range(len(testResult)):
        assert testResult[i][1] == trueResult[i], (
            f"Expected {trueResult[i]} but got {testResult[i][1]} for function {testResult[i][0]}"
        )

def test_macro_from_libs_get_ignored():
    """
    Ensure that macros from included libraries do not interfere with the metrics.
    """
    sourceCode = os.path.join(os.getcwd(), "tests", "src", "system_header_test.c")

    expectations = {
        "number_of_if_structures_without_else": (calculate_metrics.calculate_number_of_if_structures_without_else, 2),
        "cyclomatic_complexity": (calculate_metrics.calculate_cyclomatic_complexity, 3),
        "number_of_loops": (calculate_metrics.calculate_number_of_loops, 0),
        "number_of_nested_loops": (calculate_metrics.calculate_number_of_nested_loops, 0),
        "max_nesting_loop_depth": (calculate_metrics.calculate_max_nesting_loop_depth, 0),
        "number_of_pointer_arithmetic": (calculate_metrics.calculate_number_of_pointer_arithmetic, 0),
        "number_of_variables_involved_in_pointer_arithmetic": (
            calculate_metrics.calculate_number_of_variables_involved_in_pointer_arithmetic,
            0,
        ),
        "number_of_nested_control_structures": (calculate_metrics.calculate_number_of_nested_control_structures, 0),
        "maximum_nesting_level_of_control_structures": (
            calculate_metrics.calculate_maximum_nesting_level_of_control_structures,
            1,
        ),
        "maximum_of_control_dependent_control_structures": (
            calculate_metrics.calculate_maximum_of_control_dependent_control_structures,
            1,
        ),
        "maximum_of_data_dependent_control_structures": (
            calculate_metrics.calculate_maximum_of_data_dependent_control_structures,
            0,
        ),
        "number_of_variables_involved_in_control_predicates": (
            calculate_metrics.calculate_number_of_variables_involved_in_control_predicates,
            0,
        ),
    }

    for label, (metric_fn, expected_value) in expectations.items():
        test_result = calculate_metrics.run_test(sourceCode, metric_fn)
        assert test_result, f"No result returned for metric {label}"
        func_name, value = test_result[0]
        assert (
            value == expected_value
        ), f"Expected {expected_value} for metric {label} but got {value} for function {func_name}"
