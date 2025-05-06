import time
import logging
from src.tools.logger import Logger
from src.net_manager.arp_protection import set_arp_protection_level
import subprocess
import re
log = Logger(log_file='SP_Log.log', log_level=logging.DEBUG)


class Rule():
    def __init__(self, field, target, flag="", ttl=30):
        self.field = field # src, dst, arp
        self.target = target # ip address
        self.time = time.time()
        self.flag = flag
        self.ttl = ttl


class Rules():
    def __init__(self):
        self.all_rules = []
        self.past_alert_level = 1

    def add_rules(self, new_rules):
        # for rule in self.all_rules:
        #    log.log(f"===== Removed Rule - {rule.field} {rule.target}", logging.DEBUG)
        #    if time_current - rule.time > rule.ttl:
        #        self.all_rules.remove(rule)

        for rule in new_rules:
            rule_settings = rule.replace('b', '').replace("'", '')
            rule_settings = rule_settings.split('/')
            rule_settings_len = len(rule_settings)

            if 2 <= rule_settings_len <= 4:
                new_rule = Rule(rule_settings[0], rule_settings[1])

                if rule_settings_len > 2:
                    if rule_settings[2] == "None":
                        new_rule.flag == None
                    else:    
                        new_rule.flag = rule_settings[2]
                    if rule_settings_len > 3:
                        new_rule.ttl = int(rule_settings[3])
                self.all_rules.append(new_rule)
                log.log(f"===== Added Rule - {new_rule.field} {new_rule.target}", logging.DEBUG)

            else:
                log.log(f"Rule Len Invalid: {rule_settings_len} {str(rule_settings)}", logging.WARNING)

    def clear_rules(self, time_current):
        for rule in self.all_rules:

            if time_current - rule.time > rule.ttl:
                log.log(f"===== Removed Rule - {rule.field} {rule.target}", logging.DEBUG)
                self.all_rules.remove(rule)

        arp_alert_level = 1
        for rule in self.all_rules:
            if rule.field == "arp":
                arp_alert_level += 1


        if self.past_alert_level == arp_alert_level or (self.past_alert_level > 3 and arp_alert_level > 3):
            pass
        else:
            if 1 <= arp_alert_level <= 3:
                if 1 < arp_alert_level:
                    set_arp_protection_level(arp_alert_level)
                    log.log(f"===== Arp Protection Level set to - {arp_alert_level}", logging.WARNING)
            else:
                log.log(f"===== Arp Protection Level set to - {4}", logging.WARNING)
                set_arp_protection_level(4)

        self.past_alert_level = arp_alert_level

    def blocking_rules(self, src, dst, flag=""):
        for rule in self.all_rules:
            if rule.field == "src" and src == rule.target:
                if rule.flag == "" or flag == rule.flag:
                    return False
            elif rule.field == "dst" and dst == rule.target:
                if rule.flag == "" or flag == rule.flag:
                    return False

        return True
