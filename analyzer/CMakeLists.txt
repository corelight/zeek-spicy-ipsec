spicy_add_analyzer(
    NAME IPSEC
    PACKAGE_NAME IPSEC
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig consts.zeek
)