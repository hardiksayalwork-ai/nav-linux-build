"""Guard v2 completion validation,puredata,no claimedexecution."""
import struct,os
class CompletionBlocked(Exception):pass

def verify_completion(raw,expected_child,guard_wait_status):
 if len(raw)!=16:raise CompletionBlocked('exactcompletionlength')
 version,child,status,normal=struct.unpack('<IIII',raw)
 if version!=2 or child!=expected_child or normal!=1:raise CompletionBlocked('completionidentityorstate')
 if not os.WIFEXITED(guard_wait_status)or os.WEXITSTATUS(guard_wait_status)!=0:raise CompletionBlocked('guardnotexit0')
 if not os.WIFEXITED(status)or os.WEXITSTATUS(status)!=0:raise CompletionBlocked('fixturenotexit0')
 return {'guard_exit':0,'fixture_exit':0,'child_pid':child,'native_guest_executed':False}
