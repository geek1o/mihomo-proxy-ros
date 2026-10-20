"""Apply persisted overrides to legacy CGI without shell interpolation."""
import os
import sys
from .control import state_store
from .supervisor import proxy_env
if __name__=='__main__':
    env=proxy_env(state_store()); env['MP_ENV_WRAPPED']='1'
    os.execve('/bin/sh',['/bin/sh',*sys.argv[1:]],env)
