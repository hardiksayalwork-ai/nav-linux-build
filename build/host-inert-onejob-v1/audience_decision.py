OWNER={'id':246844948,'login':'hardiksayalwork-ai','node_id':'U_kgDODraOFA','type':'User'}

CODES={'not_checked','empty','individual_owner','owner_mismatch','response_invalid','pagination','external_or_ambiguous','transport_error'}

def validate_audience_diagnostic(v):
    assert type(v)is dict and set(v)=={'state','code','rows'}
    assert v['state']in ('owner_only','unknown') and v['code']in CODES
    assert type(v['rows'])is int and 0<=v['rows']<=100
    assert (v['state']=='owner_only')==(v['code']in ('empty','individual_owner'))
    return v

def audience_decision(repo,rows,status=200,link=None):
    def diag(code,n=0):return validate_audience_diagnostic({'state':'owner_only'if code in ('empty','individual_owner')else 'unknown','code':code,'rows':n})
    if type(repo)is not dict or repo.get('full_name')!='hardiksayalwork-ai/nav-linux-build' or repo.get('private')is not False:return diag('owner_mismatch')
    owner=repo.get('owner')
    if type(owner)is not dict or any(type(owner.get(k))is not type(v)or owner.get(k)!=v for k,v in OWNER.items()):return diag('owner_mismatch')
    if status!=200 or type(rows)is not list:return diag('response_invalid')
    n=min(len(rows),100)
    if link or len(rows)>=100:return diag('pagination',n)
    if not rows:return diag('empty')
    if len(rows)!=1:return diag('external_or_ambiguous',n)
    row=rows[0]
    if type(row)is not dict or any(type(row.get(k))is not type(v)or row.get(k)!=v for k,v in OWNER.items()):return diag('external_or_ambiguous',n)
    return diag('individual_owner',1)
