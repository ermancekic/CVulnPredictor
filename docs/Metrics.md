# Metrics
Static metrics are single‑point measurements used as target strategies in fuzzing to guide and evaluate which inputs yield the most useful new behaviors.

In this project, we will examine the open‑source projects enrolled in OSS‑Fuzz, apply various metrics to them, and compare the metric results with their OSS‑Fuzz issue tracker data to determine which individual metrics—or combinations of metrics—would have been most effective as a targeting strategy.

# Leopard C 

- **Lines of Code (LOC)**
  - Distinct source lines within the function body that are neither comments nor blank lines

- **Cyclomatic Complexity**
  - Approximates cyclomatic complexity by counting decision points (if/for/while/case/catch and ?:) plus one for the function entry.
- **Number of Loops**
  - Counts all loop constructs (for, while, do, and C++ range-for) in the function.
- **Number of Nested Loops**
  - Counts loops that contain at least one other loop somewhere in their subtree.
- **Max Nesting Loop Depth**
  - Returns the maximum depth of nested loop constructs within the function.

# Leopard V

## Dependency
- **Number of Parameter Variables**
  - Number of input parameters of the function
- **Number of Callee Parameters Variables**
  - Counts distinct variables that are passed as arguments to function calls within the function.

## Pointers
- **Number of Pointer Arithmetic Ops**
  - CCounts pointer-arithmetic operations (binary, compound assignments, and ++/--) involving pointer operands.
- **Number of Variables Involved in Pointer Arithmetic**
  - Counts distinct variables that participate in pointer-arithmetic operations.
- **Max Pointer Aritmethic a Variable is involved in**
  - Highest number of pointer arithmetic operations in which a single variable is involved

## Control Structures:
- **Number of Nested Control Structures**
  - Count of control structures that contain at least one other control structure in their subtree (container structures)
- **Max Nesting Level of Control Structures**
  - Maximum depth of nesting of control structures
- **Max Control-Dependent Control Structures**
  - For every control statement, counts the total number of control statements in its AST subtree (including itself) and returns the largest such total—i.e., the most control-structure-dense nested region by count (not depth).
- **Max Data-Dependent Control Structures**
  - Computes, for each variable, how many distinct control statements (if/while/for/do/switch/range-for) reference it in their condition and returns the maximum of these counts—i.e., which variable most often governs decisions.
- **Number of if without else**
  - Counting of all if-blocks without associated else
- **Number of Variables in Control Predicates**
  - Counts distinct variables used inside the conditions of control statements.

# Project/Git Metrics

- **NumChanges**
  - Total number of non-merge commits that modified the file since its creation, following renames (git log --follow).
- **LinesChanged**
  - Cumulative lines added plus lines deleted across all modifying commits (ignoring binary diffs where counts are unknown).
- **LinesNew**
  - Cumulative lines added across all modifying commits (deletions not included).
- **NumDevs**
  - Number of distinct authors (by email) who changed the file
