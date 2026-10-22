"""MSRC FixedBuild normalisation: every separator MSRC uses to list per-component builds."""
from ingest.affected.sources.microsoft import _norm_build


def test_dotnet_build_list_is_split_on_every_msrc_separator():
    for fb in ("2.0.50727.9073 AND 3.0.30729.9070 AND 4.8.4811.0",   # Windows Server 2019, 2026-Aug
               "2.0.50727.9073 & 3.0.30729.9070 & 4.8.4811.0",
               "2.0.50727.9073 and 3.0.30729.9070 and 4.8.4811.0",
               "2.0.50727.9073; 3.0.30729.9070; 4.8.4811.0",
               "2.0.50727.9073, 3.0.30729.9070, 4.8.4811.0"):
        assert _norm_build(fb, ".net_framework") == "4.8.4811.0", fb


def test_ambiguous_or_foreign_build_lists_stay_unmatchable():
    # two 4.x lines (4.8.1 and 4.8) in one remediation: not guessed
    assert _norm_build("4.8.9334.0 and 4.8.4802.0", ".net_framework") is None
    # 3.5-only remediation: no 4.x build to compare a 4.x host against
    assert _norm_build("2.0.50727.8987 AND 3.0.30729.8982", ".net_framework") is None
    # non-.NET product with two builds: unchanged behaviour (not guessed)
    assert _norm_build("1.0.43421.0 & 1.0.43422.0", "hevc_video_extensions") is None
    assert _norm_build("DSC Agent versions: 2.71.1.25, 2.70.0.30", "azure_automation") is None


def test_single_builds_unchanged():
    assert _norm_build("10.0.17763.9121", "windows_server_2019") == "10.0.17763.9121"
    assert _norm_build("5215.1000", "excel") == "16.0.5215.1000"
    assert _norm_build("https://aka.ms/OfficeSecurityReleases", "office") is None
