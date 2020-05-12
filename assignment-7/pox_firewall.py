'''
Udacity: ud436/sdn-firewall
Professor: Nick Feamster
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
from csv import DictReader


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]

# Add your global variables here ...


# Note: Policy is data structure which contains a single
# source-destination flow to be blocked on the controller.
Policy = namedtuple('Policy', ('dl_src', 'dl_dst'))


class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")

    def read_policies (self, file):
        with open(file, 'r') as f:
            reader = DictReader(f, delimiter = ",")
            policies = {}
            for row in reader:
                policies[row['id']] = Policy(EthAddr(row['mac_0']), EthAddr(row['mac_1']))
        return policies

    def _handle_ConnectionUp (self, event):
        policies = self.read_policies(policyFile)
        for policy in policies.itervalues():
            # TODO: implement the code to add a rule to block the flow
            # between the source and destination specified in each policy

            # Note: The policy data structure has two fields which you can
            # access to turn the policy into a rule. policy.dl_src will
            # give you the source mac address and policy.dl_dst will give
            # you the destination mac address

            # Note: Set the priority for your rule to 20 so that it
            # doesn't conflict with the learning bridge setup

	    #BEGIN tfairchild3@gatech.edu
	    log.debug("value of policy.dl_src=%s",policy.dl_src)
	    log.debug("value of policy.dl_dst=%s",policy.dl_dst)

	    #create the flow message object
   	    fm = of.ofp_flow_mod()
            fm.priority = 20

	    #create an action object with an empty action, this will drop the pkt
	    #but i'm not sure this is necessary as it works without it, likely because
	    #having no action object is the same thing as having an empty action object
            fm.action = of.ofp_action_output()

	    #create the match object
	    fm.match = of.ofp_match()
            fm.match.dl_src = policy.dl_src
  	    fm.match.dl_dst = policy.dl_dst

	    #send the flow message
            event.connection.send(fm)
            log.debug("done installing fm  SRC: %s",fm.match.dl_src)
            log.debug("done installing fm  DST: %s",fm.match.dl_dst)

	    #do it again, switching src and dst making it bidirectional
	    #create the match object
	    fm.match = of.ofp_match()
            fm.match.dl_src = policy.dl_dst
  	    fm.match.dl_dst = policy.dl_src

	    #send the flow message
            event.connection.send(fm)
            log.debug("done installing fm  SRC: %s",fm.match.dl_src)
            log.debug("done installing fm  DST: %s",fm.match.dl_dst)

	    #END tfairchild3@gatech.edu
            pass

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
