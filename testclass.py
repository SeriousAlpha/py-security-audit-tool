#!env python
#coding=utf-8
# 
# Author:       liaoxinxi@
# 
# Created Time: Mon 08 Dec 2014 11:03:42 AM GMT-8
# 
# FileName:     testclass.py
# 
# Description:  
# 
# ChangeLog:
class login(object):
    def __init__(self,cmd):
        self.cmd = cmd
    def execute_cmd(self, cmd):
        os.system(cmd)

    def execute_cmd1(self):
        os.popen(self.cmd)
