"""Assemble full local evidence and HTML without an LLM, SSH or SMTP.

Input manifest: {"evidence":[{"id":"e1","path":"raw.txt","target":"LAB",
"command":"show version","status":"SUCCESS","sha256":"..."}]}.
Relative paths are resolved beside the manifest. Output must be a new directory.
"""
import argparse
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile


def file_digest(path):
    with Path(path).open('rb') as handle:
        return stream_digest(handle)


def stream_digest(handle):
    hasher=hashlib.sha256()
    for chunk in iter(lambda:handle.read(1024*1024),b''):
        hasher.update(chunk)
    return hasher.hexdigest()


def summary_bundle(summary, manifest, output, renderer=None):
    """Stream each source once into ZIP; do not materialize raw in AI/HTML/RAM."""
    summary,manifest,output=map(Path,(summary,manifest,output))
    if output.exists():raise ValueError('Use a new output directory')
    brief=summary.read_bytes();brief.decode('utf-8')
    plan_bytes=manifest.read_bytes();plan=json.loads(plan_bytes.decode('utf-8-sig'))
    output.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix='.report-bundle-',dir=output.parent))
    try:
        records=[];seen=set()
        with zipfile.ZipFile(staging/'evidence.zip','w',zipfile.ZIP_DEFLATED,allowZip64=True) as archive:
            for entry in plan['evidence']:
                ident=entry['id']
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',ident) or ident in seen:
                    raise ValueError('Invalid or duplicate evidence id')
                seen.add(ident)
                source=Path(entry['path'])
                if not source.is_absolute():source=manifest.parent/source
                name='evidence/'+ident+'.raw';hasher=hashlib.sha256();size=0
                with source.open('rb') as handle, archive.open(name,'w',force_zip64=True) as sink:
                    for chunk in iter(lambda:handle.read(1024*1024),b''):
                        sink.write(chunk);hasher.update(chunk);size+=len(chunk)
                checksum=hasher.hexdigest()
                if entry.get('sha256') and entry['sha256']!=checksum:
                    raise ValueError('Evidence checksum mismatch: '+ident)
                records.append({**entry,'source_path':entry['path'],'path':name,'bytes':size,'sha256':checksum})
            archive.writestr('source_manifest.json',plan_bytes)
            archive.writestr('manifest.json',json.dumps({'evidence':records},ensure_ascii=False,indent=2).encode())
            archive.writestr('summary.md',brief)
        if renderer:
            spec=importlib.util.spec_from_file_location('summary_renderer',renderer)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            rendered=module.render_report(brief.decode('utf-8'),summary.parent.name)
        else:rendered='<!doctype html><html lang="vi"><meta charset="utf-8"><body><pre>'+html.escape(brief.decode('utf-8'))+'</pre></body></html>'
        (staging/'summary.md').write_bytes(brief)
        (staging/'report.md').write_bytes(brief)
        (staging/'report.html').write_bytes(rendered.encode())
        metadata={'schema':2,'mode':'SUMMARY','evidence':records,'summary_sha256':digest(brief),
                  'report_sha256':digest(brief),'html_sha256':digest(rendered.encode()),
                  'archive':'evidence.zip','archive_sha256':file_digest(staging/'evidence.zip')}
        (staging/'bundle.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf-8')
        staging.rename(output)
    finally:
        if staging.exists():
            assert staging.resolve().parent==output.parent.resolve() and staging.name.startswith('.report-bundle-')
            shutil.rmtree(staging)
    return {'bundle':str(output),'mode':'SUMMARY','evidence_count':len(records),
            'evidence_bytes':sum(x['bytes'] for x in records),'integrity_verified':True}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verified_html(report):
    """Verify a generated bundle before a local sender uses its HTML body."""
    report=Path(report)
    meta=json.loads((report.parent/'bundle.json').read_text(encoding='utf-8'))
    rendered=(report.parent/'report.html').read_bytes()
    if (meta['schema'] not in (1,2) or digest(report.read_bytes()) != meta['report_sha256']
            or digest(rendered) != meta['html_sha256']
            or digest((report.parent/'summary.md').read_bytes()) != meta['summary_sha256']):
        raise ValueError('Bundle changed; rebuild before sending')
    if meta['schema']==2:
        archive=report.parent/'evidence.zip'
        if meta['archive']!='evidence.zip' or file_digest(archive)!=meta['archive_sha256']:
            raise ValueError('ZIP changed; rebuild before sending')
        with zipfile.ZipFile(archive) as zipped:
            expected={x['path'] for x in meta['evidence']}|{'manifest.json','source_manifest.json','summary.md'}
            if len(zipped.namelist())!=len(expected) or set(zipped.namelist())!=expected:
                raise ValueError('Unexpected ZIP members')
            if json.loads(zipped.read('manifest.json'))['evidence']!=meta['evidence']:
                raise ValueError('ZIP manifest mismatch')
            if digest(zipped.read('summary.md'))!=meta['summary_sha256']:
                raise ValueError('ZIP summary mismatch')
            for record in meta['evidence']:
                with zipped.open(record['path']) as handle:
                    if stream_digest(handle)!=record['sha256']:raise ValueError('ZIP evidence mismatch')
        return rendered.decode('utf-8')
    for record in meta['evidence']:
        path=(report.parent/record['path']).resolve()
        if report.parent.resolve() not in path.parents or digest(path.read_bytes()) != record['sha256']:
            raise ValueError('Evidence changed; rebuild before sending')
    return rendered.decode('utf-8')


def build(summary, manifest, output, renderer=None, mode='FULL'):
    if mode=='SUMMARY':return summary_bundle(summary,manifest,output,renderer)
    if mode!='FULL':raise ValueError('Unknown report mode')
    summary, manifest, output = Path(summary), Path(manifest), Path(output)
    if output.exists():
        raise ValueError('Output directory exists; use a new bundle directory')
    brief = summary.read_bytes()
    brief.decode('utf-8')
    plan_bytes = manifest.read_bytes()
    plan = json.loads(plan_bytes.decode('utf-8-sig'))
    records, seen = [], set()
    for entry in plan['evidence']:
        ident = entry['id']
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', ident) or ident in seen:
            raise ValueError('Invalid or duplicate evidence id')
        seen.add(ident)
        source = Path(entry['path'])
        source = source if source.is_absolute() else manifest.parent / source
        raw = source.read_bytes()
        raw.decode('utf-8')  # Reject unsupported encoding, never replace/drop bytes.
        if entry.get('sha256') and digest(raw) != entry['sha256']:
            raise ValueError('Evidence checksum mismatch: ' + ident)
        entry={**entry,'sha256':digest(raw)}
        records.append((entry, raw))
    markdown = bytearray(brief)
    sections = []
    index = []
    for entry, raw in records:
        ident = entry['id']
        label = f"{ident} | {entry['target']} | {entry['command']} | status={entry['status']}"
        # Dynamic fence prevents CLI backticks from terminating the raw block.
        fence = '`' * max(3, 1 + max((len(x) for x in re.findall(r'`+', raw.decode('utf-8'))), default=0))
        markdown.extend(('\n\n## Evidence ' + label.replace('\n', ' ').replace('\r', ' ') + '\n\n' + fence + 'text\n').encode())
        markdown.extend(raw)
        markdown.extend(('\n' + fence + '\n').encode())
        sections.append('<section><h2>' + html.escape(label) + '</h2><pre>'
                        + html.escape(raw.decode('utf-8')) + '</pre></section>')
        index.append({**entry,'source_path':entry['path'],
                      'path':'evidence/'+ident+'.txt','bytes':len(raw)})
    if renderer:
        spec = importlib.util.spec_from_file_location('bundle_renderer', renderer)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        heading = module.render_report(brief.decode('utf-8'), summary.parent.name)
        if '</body>' not in heading:
            raise ValueError('Renderer must produce an HTML body')
        rendered = heading.replace('</body>', '\n'.join(sections) + '</body>')
    else:
        rendered = '<!doctype html><html lang="vi"><meta charset="utf-8"><body><pre>' + html.escape(brief.decode('utf-8')) + '</pre>' + '\n'.join(sections) + '</body></html>'
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.report-bundle-', dir=output.parent))
    try:
        (staging/'evidence').mkdir()
        for (entry, raw) in records:
            (staging/'evidence'/(entry['id']+'.txt')).write_bytes(raw)
        (staging/'summary.md').write_bytes(brief)
        (staging/'source_manifest.json').write_bytes(plan_bytes)
        (staging/'report.md').write_bytes(markdown)
        (staging/'report.html').write_bytes(rendered.encode('utf-8'))
        metadata = {'schema':1,'evidence':index,'summary_sha256':digest(brief),
                    'report_sha256':digest(markdown),'html_sha256':digest(rendered.encode('utf-8'))}
        (staging/'bundle.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2),encoding='utf-8')
        staging.rename(output)
    finally:
        if staging.exists():
            assert staging.resolve().parent == output.parent.resolve()
            assert staging.name.startswith('.report-bundle-')
            shutil.rmtree(staging)
    return {'bundle':str(output),'evidence_count':len(index),
            'evidence_bytes':sum(e['bytes'] for e in index),'integrity_verified':True}


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary',required=True,type=Path)
    parser.add_argument('--manifest',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--renderer',type=Path)
    parser.add_argument('--mode',choices=['SUMMARY','FULL'],default='SUMMARY')
    args=parser.parse_args()
    try:
        print(json.dumps(build(args.summary,args.manifest,args.output,args.renderer,args.mode),ensure_ascii=False))
        return 0
    except (OSError,ValueError,KeyError,TypeError) as error:
        print(json.dumps({'verified':False,'error_type':type(error).__name__}))
        return 1


if __name__=='__main__':raise SystemExit(main())
