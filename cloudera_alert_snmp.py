#!/usr/bin/python

"""
Docs about obtaining Cloudera MIB file
https://docs.cloudera.com/cloudera-manager/7.4.2/monitoring-and-diagnostics/topics/cm-alerts-snmp.html
"""
import json
from configparser import ConfigParser
from dateutil.parser import isoparse
from pathlib import Path
# import sys
from pysnmp.hlapi import sendNotification, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, NotificationType, ObjectIdentity
from struct import pack


def send_trap(alerts, t_conf):
    for alert in alerts:
        iterator = sendNotification(
            SnmpEngine(),
            CommunityData(t_conf['community']),
            UdpTransportTarget((t_conf['addr'], t_conf['port'])),
            ContextData(),
            'trap',
            NotificationType(
                ObjectIdentity('CLOUDERA-MANAGER-MIB', 'clouderaManagerAlert').addMibSource(str(Path.home) + '.pysnmp/mibs'),
                objects=alert
            )
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            print(errorIndication)


def iterate_alerts(json, severity):

    MAP_NOTIFICATION_CATEGORY = {
        "UNKNOWN": 0,
        "HEALTH_CHECK": 1,
        "LOG_MESSAGE": 2,
        "AUDIT_EVENT": 3,
        "ACTIVITY_EVENT": 4,
        "HBASE": 5,
        "SYSTEM": 6
    }
    MAP_EVENT_SEVERITY = {
        "UNKNOWN": 0,
        "INFORMATIONAL": 1,
        "IMPORTANT": 2,
        "CRITICAL": 3
    }

    filtered = []
    for item in json:
        attributes = item['body']['alert']['attributes']
        print(item['body']['alert']['source'])
        # print(item['body']['alert']['timestamp']['iso8601'])
        # print(attributes['PREVIOUS_HEALTH_SUMMARY'])
        # print(attributes['CURRENT_HEALTH_SUMMARY'])
        print(attributes['SERVICE_TYPE'][0])
        print(attributes['SERVICE'][0])
        print(attributes['__uuid'][0])
        print(attributes['HEALTH_TEST_RESULTS'][0]['content'])
        # print(attributes['EVENTCODE'])
        print(attributes['SEVERITY'][0])
        print(attributes['CATEGORY'][0])

        if attributes['PREVIOUS_HEALTH_SUMMARY'] != attributes['CURRENT_HEALTH_SUMMARY'] and attributes['SEVERITY'][0] == severity:
            #print("Status changed", attributes['HEALTH_TEST_RESULTS'])
            ts = isoparse(item['body']['alert']['timestamp']['iso8601'])
            snmp_time = pack('>HBBBBBB', ts.year, ts.month, ts.day, ts.hour, ts.minute, ts.second, 0)
            dic_res = {
                ('CLOUDERA-MANAGER-MIB', 'notifEventId'): attributes['__uuid'][0],
                ('CLOUDERA-MANAGER-MIB', 'notifEventOccurredTime'): snmp_time,
                ('CLOUDERA-MANAGER-MIB', 'notifEventContent'): attributes['HEALTH_TEST_RESULTS'][0]['content'],
                ('CLOUDERA-MANAGER-MIB', 'notifEventCategory'): MAP_NOTIFICATION_CATEGORY[attributes['CATEGORY'][0]],
                ('CLOUDERA-MANAGER-MIB', 'notifEventSeverity'): MAP_EVENT_SEVERITY[attributes['SEVERITY'][0]],
                ('CLOUDERA-MANAGER-MIB', 'notifEventUrl'): item['body']['alert']['source'],
                ('CLOUDERA-MANAGER-MIB', 'notifEventService'): attributes['SERVICE_TYPE'][0],
                ('CLOUDERA-MANAGER-MIB', 'notifEventCode'): attributes['EVENTCODE'][0]
                }
            try:
                dic_res[('CLOUDERA-MANAGER-MIB', 'notifEventHost')] = attributes['HOSTS'][0]
            except KeyError:
                pass
            filtered.append(dic_res)

        elif attributes['PREVIOUS_HEALTH_SUMMARY'] == attributes['CURRENT_HEALTH_SUMMARY'] or attributes['SEVERITY'][0] != severity:
            pass
            #print("Status unchanged", attributes['HEALTH_TEST_RESULTS'][0]['content'])
    return(filtered)


if __name__ == '__main__':

    config = ConfigParser()
    config.read('snmp_filtered.ini')
    service_wl = config.get('filters', 'service_whitelist')
    service_bl = config.get('filters', 'service_blacklist')
    severity = config.get('filters', 'alert_severity')
    t_conf = {}
    t_conf['addr'] = config.get('trap', 'ipaddr')
    t_conf['port'] = config.get('trap', 'port')
    t_conf['community'] = config.get('trap', 'community')

    JSON = json.load(open("test.json"))
    a = iterate_alerts(JSON, severity)
    send_trap(a, t_conf)

# DONE Alerts should be enumerated or iterated trough
# DONE Alerts should be filtered by SEVERITY, Which alerts are pass trough defined by a configuration
# DONE CURRENT_HEALTH_SUMMARY should be different from PREVIOUS_HEALTH_SUMMARY
# TODO Alerts should be filtered by service
# TODO Suppressed alerts should be filtered out
# TODO (Optional) Alerts should be filtered by CLUSTER
# TODO (Optional) Add looping over multiple messages if there are present
# TODO Add tests
# TODO Add logging