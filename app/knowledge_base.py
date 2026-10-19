"""Reference passages for the demo NSW surveying assistant.

These are short paraphrased summaries written for this assignment so the
groundedness validator has something concrete to check against. They are not
a substitute for the legislation, the Surveyor-General's directions or ICSM
standards; verify anything you rely on against the official source.
"""

KNOWLEDGE_BASE: dict[str, dict[str, str]] = {
    "KB-001": {
        "title": "GDA2020 datum",
        "text": (
            "The Geocentric Datum of Australia 2020 (GDA2020) is the current national datum adopted in NSW. "
            "GDA2020 uses the GRS80 ellipsoid. "
            "GDA2020 coordinates differ from GDA94 coordinates by approximately 1.8 metres, "
            "mainly because of the movement of the Australian tectonic plate."
        ),
    },
    "KB-002": {
        "title": "Map Grid of Australia 2020 zones",
        "text": (
            "The Map Grid of Australia 2020 (MGA2020) is a Universal Transverse Mercator projection of GDA2020. "
            "Each MGA zone is 6 degrees of longitude wide. "
            "NSW is covered by MGA zones 54, 55 and 56. "
            "The central meridians of zones 54, 55 and 56 are 141, 147 and 153 degrees east respectively. "
            "MGA uses a central scale factor of 0.9996, a false easting of 500000 metres and a false northing of 10000000 metres."
        ),
    },
    "KB-003": {
        "title": "Ground to grid distances",
        "text": (
            "A grid distance is obtained from a measured horizontal ground distance by applying the combined scale factor. "
            "The combined scale factor is the product of the point scale factor and the height factor. "
            "The point scale factor depends on how far the line is from the central meridian of the zone. "
            "The height factor accounts for the height of the line above the ellipsoid."
        ),
    },
    "KB-004": {
        "title": "Heights and AUSGeoid2020",
        "text": (
            "The Australian Height Datum (AHD) is the vertical datum used for heights in NSW. "
            "AUSGeoid2020 is used to convert GDA2020 ellipsoidal heights from GNSS to AHD heights. "
            "The AHD height is approximately the ellipsoidal height minus the AUSGeoid2020 separation value N."
        ),
    },
    "KB-005": {
        "title": "SCIMS",
        "text": (
            "SCIMS, the Survey Control Information Management System, is the NSW database of survey control marks maintained by NSW Spatial Services. "
            "SCIMS records coordinates, heights and class and order information for marks such as permanent marks (PMs) and state survey marks (SSMs). "
            "Surveyors use SCIMS to find control marks and their published coordinates before a survey."
        ),
    },
    "KB-006": {
        "title": "Protection of survey marks",
        "text": (
            "Survey marks such as PMs and SSMs are protected under the Surveying and Spatial Information Act 2002. "
            "A person must not remove, damage, destroy, displace or interfere with a survey mark without lawful authority. "
            "A survey mark that has been destroyed or disturbed should be reported to NSW Spatial Services."
        ),
    },
    "KB-007": {
        "title": "Registration of surveyors",
        "text": (
            "In NSW, land surveyors and mining surveyors are registered by the Board of Surveying and Spatial Information (BOSSI). "
            "Only a registered land surveyor may carry out and certify a cadastral survey, such as a survey that defines property boundaries for a plan lodged for registration."
        ),
    },
    "KB-008": {
        "title": "Boundary identification and fences",
        "text": (
            "A boundary identification survey determines the position of the title boundaries relative to occupation such as fences and buildings. "
            "Fences do not necessarily follow the title boundary. "
            "Disputes between neighbours about dividing fences in NSW are generally dealt with under the Dividing Fences Act 1991. "
            "Legal advice should be sought for a boundary dispute."
        ),
    },
    "KB-009": {
        "title": "Deposited plans and lot descriptions",
        "text": (
            "A deposited plan (DP) is a plan registered by NSW Land Registry Services. "
            "Land parcels are commonly described by lot and plan number, for example Lot 12 DP 123456. "
            "A plan of subdivision prepared from a survey must be certified by a registered land surveyor."
        ),
    },
    "KB-010": {
        "title": "Survey work near overhead powerlines",
        "text": (
            "Survey work near overhead powerlines requires keeping safe approach distances from energised conductors. "
            "Survey staffs, prism poles and GNSS antenna poles can conduct electricity and must not be raised near overhead lines. "
            "Work near electrical assets must follow the network operator's requirements and the site safety plan."
        ),
    },
    "KB-011": {
        "title": "RTK GNSS and CORSnet-NSW",
        "text": (
            "Real-time kinematic (RTK) GNSS positioning uses corrections from a base station or a network to achieve centimetre-level positions. "
            "CORSnet-NSW is the NSW network of continuously operating reference stations operated by NSW Spatial Services. "
            "RTK results should be checked by occupying known control marks."
        ),
    },
    "KB-012": {
        "title": "Traverse misclose",
        "text": (
            "Traverse misclose is the difference between the computed and the known closing position of a traverse. "
            "Linear misclose is often expressed as a ratio of the misclose to the total traverse length, for example 1 in 20000. "
            "A traverse misclose should be within the tolerance of the applicable survey standard before an adjustment such as the Bowditch rule is applied."
        ),
    },
}
