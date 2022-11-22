import logging
from pathlib import Path

import angr
from angr_platforms.ebpf import ArchExtendedBPF

# TODO debug
logging.root.setLevel(logging.DEBUG)

TEST_PROGRAMS_BASE = Path(__file__).parent.parent / "test_programs" / "ebpf"

def test_prog_always_returns_42(filename: str) -> None:
    proj = angr.Project(TEST_PROGRAMS_BASE / filename)
    assert isinstance(proj.arch, ArchExtendedBPF)

    solver = proj.factory.entry_state().solver
    simgr = proj.factory.simulation_manager()
    simgr.explore()

    assert len(simgr.deadended) == 1
    assert solver.eval_exact(simgr.deadended[0].regs.R0, 1) == [42]

def test_trivial_return():
    test_prog_always_returns_42('return_42.o')

def test_branched_return():
    test_prog_always_returns_42('return_if.o')

if __name__ == "__main__":
    test_trivial_return()
    test_branched_return()
