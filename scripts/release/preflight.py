#!/usr/bin/env python3
"""Read-only GitHub checks before the manually approved publication job."""
import argparse
import json
import fnmatch
import urllib.error
import os
import urllib.parse
import urllib.request
from common import require, subject, timevalue
from console_assets import validate_selection


def github(path):
    token = os.environ.get('GH_TOKEN')
    require(token, 'GITHUB_TOKEN_REQUIRED')
    request = urllib.request.Request('https://api.github.com/' + path, headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    require(len(data) <= 4 * 1024 * 1024, 'GITHUB_RESPONSE_LIMIT')
    return json.loads(data)


def check(repository, tag, commit):
    subject(repository, tag, commit)
    require(os.environ.get('GITHUB_REPOSITORY') == repository and os.environ.get('GITHUB_REF') == 'refs/tags/' + tag and os.environ.get('GITHUB_SHA') == commit, 'TAG_WORKFLOW_REQUIRED')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'MANUAL_WORKFLOW_REQUIRED')
    require(github('repos/' + repository + '/commits/' + tag)['sha'] == commit, 'REMOTE_TAG_CHANGED')
    workflows = github('repos/' + repository + '/actions/workflows/ci.yml/runs?head_sha=' + commit + '&per_page=100')['workflow_runs']
    matches = [r for r in workflows if r['head_sha'] == commit and r['path'] == '.github/workflows/ci.yml' and r['event'] == 'push']
    require(matches and max(matches, key=lambda r: r['run_number'])['conclusion'] == 'success', 'EXACT_COMMIT_CI_REQUIRED')


def console_policy(repository, tag, first, previous_tag, previous_commit):
    validate_selection(first,previous_tag,previous_commit,tag)
    published=[]
    for page in range(1,11):
        releases=github('repos/'+repository+'/releases?per_page=100&page='+str(page))
        require(isinstance(releases,list),'PREVIOUS_RELEASE_LIST_FORMAT')
        published.extend(r for r in releases if not r.get('draft') and any(a.get('name')=='console.oci.tar' for a in r.get('assets',[])))
        if len(releases)<100: break
    else: raise ValueError('PREVIOUS_RELEASE_LIST_LIMIT')
    if first:
        require(not published,'CONSOLE_FIRST_RELEASE_ALREADY_EXISTS')
    else:
        require(published,'PREVIOUS_CONSOLE_RELEASE_NOT_PUBLISHED')
        latest=max(published,key=lambda r:timevalue(r['published_at']))
        require(latest['tag_name']==previous_tag,'LATEST_PUBLISHED_CONSOLE_RELEASE_REQUIRED')
        require(github('repos/'+repository+'/commits/'+previous_tag)['sha']==previous_commit,'PREVIOUS_RELEASE_COMMIT_MISMATCH')


def publication_policy(repository, tag):
    environment = github('repos/' + repository + '/environments/production-release')
    require(any(r.get('type') == 'required_reviewers' and r.get('prevent_self_review') is True and r.get('reviewers') for r in environment.get('protection_rules', [])), 'ENVIRONMENT_REVIEW_REQUIRED')
    require(environment.get('deployment_branch_policy', {}).get('custom_branch_policies') is True, 'ENVIRONMENT_TAG_POLICY_REQUIRED')
    policies = github('repos/' + repository + '/environments/production-release/deployment-branch-policies?per_page=100')['branch_policies']
    require(any(p.get('type') == 'tag' and fnmatch.fnmatchcase(tag, p['name']) for p in policies), 'ENVIRONMENT_TAG_DENIED')
    # A matching active repository tag ruleset must prevent update/deletion.
    # Organization-only rulesets require an equivalent repository ruleset here;
    # no approximation of inherited rules or silent acceptance on API errors.
    rulesets = github('repos/' + repository + '/rulesets?includes_parents=false&per_page=100')
    protected = False
    for summary in rulesets:
        if summary.get('target') != 'tag' or summary.get('enforcement') != 'active': continue
        ruleset = github('repos/' + repository + '/rulesets/' + str(summary['id']))
        refs = ruleset.get('conditions', {}).get('ref_name', {})
        ref = 'refs/tags/' + tag
        includes = any(p == '~ALL' or fnmatch.fnmatchcase(ref, p) for p in refs.get('include', []))
        excludes = any(p == '~ALL' or fnmatch.fnmatchcase(ref, p) for p in refs.get('exclude', []))
        types = {r['type'] for r in ruleset.get('rules', [])}
        if includes and not excludes and {'update', 'deletion'} <= types: protected = True
    require(protected, 'IMMUTABLE_TAG_RULESET_REQUIRED')
    try:
        github('repos/' + repository + '/releases/tags/' + tag)
    except urllib.error.HTTPError as error:
        require(error.code == 404, 'RELEASE_LOOKUP_FAILED')
    else:
        raise ValueError('RELEASE_ALREADY_EXISTS')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--console-first-release',action='store_true')
    parser.add_argument('--console-previous-tag',default='')
    parser.add_argument('--console-previous-commit',default='')
    args = parser.parse_args()
    check(args.repository, args.tag, args.commit)
    console_policy(args.repository,args.tag,args.console_first_release,args.console_previous_tag,args.console_previous_commit)
