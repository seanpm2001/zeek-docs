:tocdepth: 3

policy/frameworks/spicy/record-spicy-batch.zeek
===============================================
.. zeek:namespace:: SpicyBatch

Saves all input traffic in Spicy's batch format.

:Namespace: SpicyBatch

Summary
~~~~~~~
Redefinable Options
###################
======================================================================== =
:zeek:id:`SpicyBatch::filename`: :zeek:type:`string` :zeek:attr:`&redef` 
======================================================================== =

Redefinitions
#############
============================================================================== =
:zeek:id:`tcp_content_deliver_all_orig`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`tcp_content_deliver_all_resp`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`udp_content_deliver_all_orig`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`udp_content_deliver_all_resp`: :zeek:type:`bool` :zeek:attr:`&redef` 
============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: SpicyBatch::filename
   :source-code: policy/frameworks/spicy/record-spicy-batch.zeek 6 6

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"batch.dat"``



