import angr
import sys

project = angr.Project("./hash2");
state = project.factory.entry_state()

simmgr = project.factory.simulation_manager(state)

simmgr.explore(find=lambda state: b"Found" in state.posix.dumps(1))

if simmgr.found:
    for byte in simmgr.found[0].posix.dumps(0):
        print(hex(byte), end=',')
    print("")