"""Fresh read-only GitHub audience/cache guard. No writes, no retries."""
import json,urllib.request
from audience_decision import audience_decision
BASE='https://api.github.com/repos/hardiksayalwork-ai/nav-linux-build'
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a):return None

def guard(token,cache_raw):
 opener=urllib.request.build_opener(NoRedirect())
 def get(suffix):
  req=urllib.request.Request(BASE+suffix,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','Cache-Control':'no-store','X-GitHub-Api-Version':'2022-11-28'})
  with opener.open(req,timeout=30)as r:
   raw=r.read(1048577)
   if r.status!=200 or r.headers.get('Link')or len(raw)>1048576:raise ValueError('incomplete_guard_response')
  def unique(pairs):
   d={}
   for k,v in pairs:
    if k in d:raise ValueError('duplicate_guard_key')
    d[k]=v
   return d
  return json.loads(raw,object_pairs_hook=unique)
 repo=get('');rows=get('/collaborators?affiliation=direct&per_page=100&page=1')
 a=audience_decision(repo,rows)
 if a['state']!='owner_only':raise ValueError('owner_only_audience_unverified')
 actual=get('/actions/caches?per_page=100');expected=json.loads(cache_raw)
 rows=actual['actions_caches']
 if actual['total_count']!=len(rows)or len(rows)!=45:raise ValueError('exact45_count')
 observed={str(x['id']):{'key':x['key'],'bytes':x['size_in_bytes']}for x in rows}
 if len(observed)!=45 or observed!=expected['protected_caches']:raise ValueError('exact45_identity')
 headroom=expected['limits']['capacity_bytes']-sum(x['bytes']for x in observed.values())
 if headroom<expected['limits']['reserve_bytes']:raise ValueError('cache_reserve')
 return {'audience':'owner_only','protected_cache_count':45,'no_cache_mutation':True}
