:tocdepth: 3

<Spicy-Syslog>
==============



Summary
~~~~~~~
Events
######
============================================= ========================================
:zeek:id:`syslog_message`: :zeek:type:`event` Generated for monitored Syslog messages.
============================================= ========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: syslog_message
   :source-code: <Spicy-Syslog> 0 0

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, facility: :zeek:type:`count`, severity: :zeek:type:`count`, msg: :zeek:type:`string`)

   Generated for monitored Syslog messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Syslog>`__ for more
   information about the Syslog protocol.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param facility: The "facility" included in the message.
   

   :param severity: The "severity" included in the message.
   

   :param msg: The message logged.
   
   .. note:: Zeek currently parses only UDP syslog traffic.


