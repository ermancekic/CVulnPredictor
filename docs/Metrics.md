# Metrics
Static metrics are single‑point measurements used as target strategies in fuzzing to guide and evaluate which inputs yield the most useful new behaviors.

In this project, we will examine the open‑source projects enrolled in OSS‑Fuzz, apply various metrics to them, and compare the metric results with their OSS‑Fuzz issue tracker data to determine which individual metrics—or combinations of metrics—would have been most effective as a targeting strategy.

# Leopard C 

- **Cyclomatic Complexity**
  - Number of linearly independent paths in a function
  - Approximate cyclomatic complexity by counting decision-point tokens
  - each 'if', 'for', 'while', 'case', 'catch'
  - each ternary '?'
  - plus 1 for the method's entry point.
- **Number of Loops**
  - Total number of all loops in the function body
  - Considered loop kinds are: for-, while-, do-while- and C++ ranged based for loops
- **Number of Nested Loops**
  - The Number of nested loops
  - Considered loop kinds are: for-, while-, do-while- and C++ ranged based for loops
- **Max Loop Nesting Level**
  - Maximum depth of loop nesting
  - Considered loop kinds are: for-, while-, do-while- and C++ ranged based for loops

# Leopard V

## Dependency
- **Number of Parameter Variables**
  - Number of input parameters of the function
- **Number of Variables as Callee Parameters**
  - Number of variables that are used as arguments when calling other functions

## Pointers
- **Number of Pointer Arithmetic Ops**
  - Counting of all pointer arithmetic operations
  - Consideres operations are: Binary and Unary operators on pointers and array subscripting
- **Number of Variables Involved in Pointer Arithmetic**
  - Number of different variables that are included in pointer arithmetic
- **Max Pointer Ops per Variable**
  - Highest number of pointer arithmetic operations in which a single variable is involved

## Control Structures:
- **Number of Nested Control Structures**
  - Total number of nested control structures
- **Max Control Nesting Level**
  - Maximum depth of nesting of control structures
- **Max Control-Dependent Control Structures**
  - Maximum number of structures that are control flow-dependent
- **Max Data-Dependent Control Structures**
  - Maximum number of structures that are data flow-dependent
- **Number of if without else**
  - Counting of all if-blocks without associated else
- **Number of Variables in Control Predicates**
  - Number of variables used in the conditions (predicates) of control structures

# Project/Git Metrics

- **NumChanges**
  - Number of commits that touched a file (git log --follow)
- **LinesChanged**
  - Cumulative lines added + deleted across the file's history
- **LinesNew**
  - Cumulative lines added across the file's history
- **NumDevs**
  - Number of distinct authors (by email) who changed the file
