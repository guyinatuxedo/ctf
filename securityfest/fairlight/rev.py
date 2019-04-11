# This script is based off of: https://github.com/angr/angr-doc

# Import angr and claripy
import angr
import claripy

# Establish the angr project
target = angr.Project('./fairlight', load_options={"auto_load_libs": False})

# Establish the input as a 14*8 = 112 bit vector for 14 characters
inp_argv1 = claripy.BVS("inp_argv1", 0xe * 8)

# Establish the entry state as the binary running with our input as argv1
entry_state = target.factory.entry_state(args=["./fairlight", inp_argv1])

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Symbolically execute the binary until find / avoid conditions met 
simulation.explore(find = 0x401a73, avoid = 0x40074d)

# Parse in the correct input
solution = simulation.found[0]

# Print the correct input
print solution.solver.eval(inp_argv1, cast_to=bytes)
