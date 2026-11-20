import json,os,time,urllib.request
from pathlib import Path
from bson import BSON
from labs.shared.core import database,reset,Blocked

def main(run):
    db=database(run)
    if run.wants(1,2):schema_and_working_set(run,db)
    if run.wants(3):url_threat_analysis(run,db)

def url_threat_analysis(run,db):
    """Activity 3: analyse a URL with URLhaus, ThreatFox, Botvrij.eu and GCVE; store de-duplicated findings."""
    os.environ['CTI_DB']=db.name
    import app.cti as cti
    cti.DB_NAME=db.name
    cti.ensure_indexes()
    sync=cti.sync_botvrij()
    run.emit('botvrij_sync',**{k:v for k,v in sync.items() if k in('state','events','indicators','updated_events','failed_events','error')})
    if cti.abusech_key():
        tf=cti.sync_threatfox()
        run.emit('threatfox_sync',**{k:v for k,v in tf.items() if k in('state','imported','indicators','error')})
    sample=os.getenv('CTI_SAMPLE_URL')
    if not sample:
        doc=db.botvrij_indicators.find_one({'type':'url','match_url':{'$exists':True}},sort=[('event_date',-1)])
        sample=doc['value'] if doc else 'http://example.com/'
    try:report=cti.analyse(sample)
    except Exception as exc:
        run.emit('external_check_blocked',reason=f'URL analysis could not reach intelligence sources: {type(exc).__name__}');return
    run.emit('url_analysis',url=report['url'],verdict=report['verdict'],risk_score=report['risk_score'],
             sources=report['sources_checked'],reasons=report['reasons'],**report['dedup'])
    run.emit('deduplicated_findings',rows=[{'kind':f['kind'],'value':f['value'],'sources':', '.join(f['sources'])} for f in report['findings']])
    run.emit('mongodb_storage',database=db.name,url_analyses=db.url_analyses.count_documents({}),
             threat_findings=db.threat_findings.count_documents({}),botvrij_indicators=db.botvrij_indicators.count_documents({}))
    if not cti.abusech_key():
        run.emit('external_check_blocked',reason='ABUSECH_AUTH_KEY not set: URLhaus and ThreatFox were not queried (free key at https://auth.abuse.ch/).')

def schema_and_working_set(run,db):
    records=json.loads(Path('data/threats.json').read_text())
    col=reset(db,'reports',records)
    reset(db,'sources',[{'_id':r['source'],'url':r['source']} for r in {r['source']:r for r in records}.values()])
    alternate=reset(db,'referenced_reports',[{**r,'source_id':r['source']} for r in records])
    alternate.update_many({}, {'$unset':{'source':''}})
    for c in [col,alternate]:
        sizes=[len(BSON.encode(d)) for d in c.find()]
        run.emit('bson_size',design=c.name,actual_count=len(sizes),average=sum(sizes)/len(sizes),maximum=max(sizes))
    n=run.count(100000);work=reset(db,'working_set')
    for start in range(0,n,1000):work.insert_many([{'_id':i,'payload':run.random.randbytes(1950)} for i in range(start,min(n,start+1000))])
    stop=time.monotonic()+(60 if run.mode=='full' else 20);next_sample=0;reads=0
    while time.monotonic()<stop:
        work.find_one({'_id':run.random.randrange(n)});reads+=1
        if time.monotonic()>=next_sample:
            cache=db.client.admin.command('serverStatus').get('wiredTiger',{}).get('cache',{})
            requested=cache.get('pages requested from the cache',0);disk=cache.get('pages read into cache',0)
            run.emit('cache',actual_count=n,reads=reads,metrics=cache,estimated_hit_ratio=max(0,1-disk/requested) if requested else None)
            next_sample=time.monotonic()+10
    source=os.getenv('ANNUAL_REPORTS_URL')
    if source:
        from labs.shared.report_check import newer_reports
        known={r['source'] for r in records}
        run.emit('read_only_newer_reports',url=source,rows=newer_reports(source,known,int(os.getenv('REPORT_MIN_YEAR','2025'))))
    else:run.emit('external_check_blocked',reason='ANNUAL_REPORTS_URL not set. Candidate repository: https://github.com/22/annual-security-reports; assigned source identity is unconfirmed.')
    import subprocess
    archive=run.directory/'reports.archive'
    subprocess.run(['mongodump','--uri',os.environ['MONGO_URI'],'--db',db.name,'--collection','reports','--archive='+str(archive)],check=True,capture_output=True)
    run.emit('metadata_dump',archive=str(archive),attribution='Ubuntu advisories; ctidigest.com is a discovery reference, not claimed as the author of these advisories.')
    run.emit('app_reuse',command='./scripts/demo.sh')
