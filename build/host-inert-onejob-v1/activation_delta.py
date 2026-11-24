"""Exact reviewable activationdelta applied as DATAonly. Not built/run.

Onlyremovesguard'sliteralreturn119statement,keepingallotherbytesidentical.
AuthoritytoexecuteNEVERcomesfrommatchingthisdelta.
"""
import hashlib,difflib
INERT_LINE=' if(argc>=0)return 119; /* NONNEGOTIABLE SOURCE-REVIEW HARDSTOP */\n'
# Actualsourcewordingboundbycaller'sreviewedpin,belowacceptsexactonecurrentline.
CURRENT_LINE=' if(argc>=0)return 119; /* NONNEGOTIABLE SOURCE-REVIEW HARDSTOP */\n'
class ActivationBlocked(Exception):pass

def derive_active(inert_bytes,expected_inert_sha):
 if hashlib.sha256(inert_bytes).hexdigest()!=expected_inert_sha:raise ActivationBlocked('inertsourcepin')
 text=inert_bytes.decode('utf-8')
 lines=[line for line in text.splitlines(keepends=True)if 'if(argc>=0)return 119;'in line]
 if len(lines)!=1:raise ActivationBlocked('oneexacthardstoprequired')
 allowed=' if(argc>=0)return 119; /* NONNEGOTIABLE SOURCE-REVIEW HARDSTOP */\n'
 if lines[0]!=allowed:raise ActivationBlocked('unreviewedhardstopline')
 active=text.replace(allowed,' /* Activevariant:REVIEWLABELONLY;NOauthority;fixedHOSTONLYscope. */\n',1).encode()
 delta=''.join(difflib.unified_diff(text.splitlines(keepends=True),active.decode().splitlines(keepends=True),fromfile='guard-inert119.c',tofile='guard-active-HOSTONLY.c'))
 return {'source':active,'source_sha256':hashlib.sha256(active).hexdigest(),'delta':delta,'inert_source_sha256':expected_inert_sha,'compiled':False,'execution_authorized':False}
