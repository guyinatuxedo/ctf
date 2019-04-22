# This script is based off of: https://github.com/elklepo/pwn/blob/master/PlaidCTF_2019/i_can_count/exploit.py

# Import angr & Claripy

import angr
import claripy

# Establish the target
target = angr.Project('i_can_count_8484ceff57cb99e3bdb3017f8c8a2467', auto_load_libs=False)

# Establish the entry state to be the start of the check_flag function
state = target.factory.blank_state(addr = target.loader.find_symbol('check_flag').rebased_addr)

# Establish the input angr has control over, as a array with nineteen bytes, values between ASCII 0 - 9 (0x30 - 0x39)
flag_input = claripy.BVS('flag', 8*19)
for i in flag_input.chop(8):
	state.solver.add(state.solver.And(i >= '0', i <= '9'))

# Set the area of memory in the binary where our input is set 
state.memory.store(target.loader.find_symbol('flag_buf').rebased_addr, flag_input)

# Establish the simulation
simulation = target.factory.simulation_manager(state)

# Establish the addresses wh
success = 0xf87 + target.loader.main_object.min_addr
failure = 0xfae + target.loader.main_object.min_addr

# Setup the simulation
simulation.use_technique(angr.exploration_techniques.Explorer(find = success, avoid= failure))

# Run the simulation
print simulation.run()

# Parse out the solution, in integer form
flag_integer = simulation.found[0].solver.eval(flag_input)

# Go through and convert the solution to a string
flag = ""
for i in xrange(19):
	flag = chr(flag_integer & 0xff) + flag
	flag_integer = flag_integer >> 8

# Print the flag
print "flag: PCTF{" + flag + "}" 
