"""Guard location hint parser,never authority. Native ABI little-endian x86_64.
Actual pipe must be exclusive controller-created endpoint inherited only by
pinned guard. Independent proc/pidfd identity remains required before release.
"""
import struct
from placement_observation import parse_stat,PlacementBlocked
class HandoffBlocked(Exception):pass

def verify_hint(raw,owned_guard_pid,guard_before,guard_after,child_before,child_after):
 if len(raw)!=16:raise HandoffBlocked('handoff exact length')
 version,guard,child,reserved=struct.unpack('<IIII',raw)
 if version!=1 or reserved or guard!=owned_guard_pid or child<2 or child==guard:raise HandoffBlocked('handoff identity fields')
 gb=parse_stat(guard_before);ga=parse_stat(guard_after);cb=parse_stat(child_before);ca=parse_stat(child_after)
 if gb!=ga or cb!=ca:raise HandoffBlocked('identity changed during observation')
 if gb['pid']!=guard or cb['pid']!=child or cb['ppid']!=guard or cb['state']not in ('T','t'):raise HandoffBlocked('independent parent/stopped observation mismatch')
 return {'guard_pid':guard,'child_pid':child,'child_starttime':cb['starttime'],'requires_owned_pidfd_binding':True,'membership_verified':False,'release_permission':False}
