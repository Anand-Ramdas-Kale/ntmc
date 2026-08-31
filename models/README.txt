BAKMM-IoD SPDL MODELS
======================

Files
-----
01_registration.spdl
    Section 4.1 registration/credential provisioning.
    This is a computation model; registration is not an open-channel
    Scyther handshake in the paper.

02_authentication.spdl
    Section 4.2 drone <-> ground station server.
    Received M2/M4/M6 values are constrained as symbolic patterns.

03_key_management.spdl
    Section 4.3 ground station server <-> cloud server.
    Received m2/m4/m6 values are constrained as symbolic patterns.

04_blockchain.spdl
    Section 4.5 symbolic security-relevant blockchain transport.
    Full pBFT consensus is intentionally not modelled as a Scyther
    authentication protocol.

Run
---
SCYTHER=/path/to/scyther-linux-v1.3.0/Scyther/scyther-linux

$SCYTHER 01_registration.spdl
$SCYTHER 02_authentication.spdl
$SCYTHER 03_key_management.spdl
$SCYTHER 04_blockchain.spdl

Important
---------
The original paper's Figure 3/4 SPDL uses receive-side expressions as
patterns. An earlier model that used unconstrained variables such as

    var m3;
    var m4;
    var m5;

and then received them directly did NOT model the protocol's equality
checks. That can cause false authentication failures.

The models here preserve the equations in Sections 4.2 and 4.3 and use
the receive patterns to represent the paper's checks M2'=M2, M4'=M4 and
M6'=M6.

Timestamp freshness is represented by fresh Timestamp/Nonce values.
The actual numerical test |T-T*| <= DeltaT is not directly represented
because Scyther's symbolic model does not evaluate wall-clock
differences. Fresh session values are used to capture the protocol
freshness assumption.

Communication sizes in the technical report are computed from the
paper's stated sizes:
identity = 160 bits
random number = 160 bits
ECC point = 320 bits
SHA-256 hash = 256 bits
timestamp = 32 bits

The paper's Table 9 reports 1792 bits for its 3-message BAKMM-IoD
authentication/key-establishment exchange. Direct recomputation from
the stated field sizes for the three messages gives 1696 bits; the
difference should be reported as a discrepancy rather than silently
changing the field sizes.


Paper correspondence
---------------------
The authentication model follows the equations in Section 4.2 and the
key-management model follows Section 4.3. In particular, the receive-side
patterns model the paper's checks M2'=M2, M4'=M4 and M6'=M6.

The original paper's Figure 3/4 implementation also models authentication
by putting the expected symbolic expressions directly into recv() patterns.
This is the key difference from the earlier model that declared m3/m4/m5
as unconstrained variables.

Important v1.3.0 compatibility note
-----------------------------------
The BAKMM paper's Figures 3 and 4 declare `cat` explicitly as:
    const cat:Function;
The current authentication and key-management models therefore declare it
before using cat(...). Earlier versions of these files omitted this declaration,
which caused Scyther v1.3.0 to report: "undeclared symbol cat".
