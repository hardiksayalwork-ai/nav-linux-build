"""Combined first-host driver SOURCE. run() unconditionalrefusal.

Privateimplementation notcalled:compile inert->active->receiptboundconfig->
onefixedhostcase->FDclosedreceipt. NO CLI that canactivate by userargument.
"""
from pathlib import Path
import hashlib,os
from compile_only_receipt_PROPOSAL import compile_only_UNINVOKED,digest
from active_build_receipt_PROPOSAL import build_active_UNINVOKED
from combined_phase_gate import CombinedGate,EXPECTED_SCOPE
from integrated_host_lifecycle_PROPOSAL import _lifecycle_UNREACHABLE
from fd_identity_snapshot import snapshot,verify_closed
from fresh_host_admission_PROPOSAL import fresh_admission
from toolchain_closure_PROPOSAL import bind_toolchain_UNINVOKED
class CombinedBlocked(Exception):pass

def run(*args,**kwargs):raise CombinedBlocked('notapproved:combinedsourceonly')

def _combined_UNREACHABLE(reviewed,root):
 # reviewedmustcomeONLYfroma futureliteralreviewedsource-manifestconstant.
 # CurrentglobalanchorisUNSET;thisprivatebodyisnotanexposedexecutionpath.
 root=Path(root)
 if root.exists():raise CombinedBlocked('freshrunrootrequired')
 admission=fresh_admission(reviewed['delegated_parent'],reviewed['compiler'])
 root.mkdir(mode=0o700)
 toolchain=bind_toolchain_UNINVOKED(reviewed['compiler'])
 # Internalproofmodel:trustedstandardfreshGitHubhosttoolchainONLYfortinyinertcase.
 # Inventorygapsarerecorded,notmisrepresentedhermeticorgeneralcontainment.
 toolchain['trust_model']='TRUSTED_STANDARD_GITHUB_HOST_TOOLCHAIN_NONHERMETIC_TINYCASE_ONLY'
 before=snapshot();gate=CombinedGate(reviewed['manifest_sha'])
 inert=compile_only_UNINVOKED(reviewed['source_dir'],root/'inert',reviewed['inert_source_pins'],reviewed['compiler'])
 gate.inert_receipt(inert)
 active=build_active_UNINVOKED(Path(reviewed['source_dir'])/'outer_stopped_guard_PROPOSAL.c',reviewed['inert_source_pins']['outer_stopped_guard_PROPOSAL.c'],reviewed['active_source_sha'],reviewed['compiler'],root/'active')
 raw=Path(active['binary_path']).read_bytes();gate.active_receipt(active,reviewed['active_source_sha'],raw);gate.prepare_case(EXPECTED_SCOPE)
 fixture=next(x for x in inert['outputs']if x['name']=='fixture-inert0')
 config={'authority':'UNSET','guard_path':active['binary_path'],'guard_sha':active['binary_sha256'],'guard_bytes':active['binary_bytes'],'fixture_path':fixture['path'],'fixture_sha':fixture['sha256'],'fixture_bytes':fixture['bytes'],'delegated_parent':reviewed['delegated_parent'],'unique_group':reviewed['unique_group'],'expected_cgroup_path':reviewed['expected_cgroup_path']}
 result=_lifecycle_UNREACHABLE(config)
 after=snapshot();fd_receipt=verify_closed(before,after)
 # DirectorylistingFDnumbersmaydifferbetweenreads;futurecollector mustuse
 # fstat-liveidentitysnapshots,notrawnames.Thiscomparisonisfailclosedonly.
 return {'admission':admission,'toolchain':toolchain,'scope':EXPECTED_SCOPE,'inert_receipt':inert,'active_receipt':active,'lifecycle':result,'fd_receipt':fd_receipt,'upstream_tests':'EXCLUDED_NOT_RUN_NOT_PASSED','guest_or_native':False,'authority_from_receipt':False}
