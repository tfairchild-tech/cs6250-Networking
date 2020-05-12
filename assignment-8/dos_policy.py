# Udacity
# Computer Networking
# Assignment 8: Applications of SDN
#
# Professor: Nick Feamster
# Teaching Assistant: Ben Jones
#
################################################################################
# Resonance Project                                                            #
# Resonance implemented with Pyretic platform                                  #
# author: Hyojoon Kim (joonk@gatech.edu)                                       #
# author: Nick Feamster (feamster@cc.gatech.edu)                               #
# author: Muhammad Shahbaz (muhammad.shahbaz@gatech.edu)                       #
################################################################################

from pyretic.lib.corelib import *
from pyretic.lib.std import *

from ..policies.base_policy import *
from ..drivers.sflow_event import *
from ..globals import *

HOST = 'localhost'
PORT = 8008

class DDoSPolicy(BasePolicy):
    
    def __init__(self, fsm):
        self.fsm = fsm
        
    def allow_policy(self):
        return passthrough
    
    def action(self):
        if self.fsm.trigger.value == 0:
            # TODO- set the policy for this application
            #
            # To set the policy for this application, implement the
            # following steps:
            #
            # 1. get the list of hosts in ddos attacker state
	    # BEGIN tfairchild3@gatech.edu
	    all_flows = self.fsm.get_flows('ddos-attacker')
            f_srcip = None
	    for flow in all_flows:
		if eval(flow)['srcip'] != None:
	 		f_srcip = eval(flow)['srcip']	
             
	    # 2. match the incoming packet's source and destination ip
            #  against that list of hosts (using pyretic predicates
            #  i.e., "match", "modify", and "if_" etc)
            match_ddos = self.fsm.get_policy('ddos')
            match_src  = match(srcip=IPAddr(str(f_srcip)))
            match_dst  = match(dstip=IPAddr(str(f_srcip)))

            # 3. if there is a match apply drop policy, else apply
            #  policy passthrough and return the policy you just
            #  created
            p1 = if_( ( match_ddos | match_src | match_dst ), drop, self.allow_policy())                                  
            # END tfairchild3@gatech.edu

            # Parallel composition- return the policy that you created
            return p1

        else:
            return self.turn_off_module(self.fsm.comp.value)
