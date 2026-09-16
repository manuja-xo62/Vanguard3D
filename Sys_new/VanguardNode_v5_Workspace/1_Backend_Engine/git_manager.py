import git
import os
from datetime import datetime

def create_remediation_pr(repo_path: str, scan_id: str, compliance_score: int):
    try:
        abs_path = os.path.abspath(repo_path)
        if not os.path.exists(abs_path):
            return {'status': 'FAILED', 'error': f'Path does not exist: {abs_path}'}
        try:
            repo = git.Repo(abs_path)
        except git.exc.InvalidGitRepositoryError:
            repo = git.Repo.init(abs_path)
        if not repo.heads:
            readme_path = os.path.join(abs_path, 'README.md')
            if not os.path.exists(readme_path):
                with open(readme_path, 'w') as f:
                    f.write('# Vanguard Security Remediation\n')
            repo.index.add(['README.md'])
            repo.index.commit('Initial commit by Vanguard Engine')
        if repo.heads:
            primary = repo.heads[0]
            for candidate in ('main', 'master'):
                if candidate in repo.heads:
                    primary = repo.heads[candidate]
                    break
            primary.checkout()
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        clean_scan_id = scan_id.replace(' ', '_') if scan_id else 'manual'
        branch_name = f'security/vanguard-remediation-{clean_scan_id}-{timestamp}'
        new_branch = repo.create_head(branch_name)
        new_branch.checkout()
        repo.git.add(A=True)
        if repo.is_dirty(untracked_files=True):
            commit_message = f'SecOps: Automated Remediation for {clean_scan_id}\n\nCompliance Score: {compliance_score}%'
            repo.index.commit(commit_message)
        pushed_to_remote = False
        if 'origin' in [remote.name for remote in repo.remotes]:
            try:
                origin = repo.remote(name='origin')
                origin.push(branch_name)
                pushed_to_remote = True
            except Exception as push_err:
                print(f'[Warning] Remote push skipped/failed: {push_err}')
        return {'status': 'SUCCESS', 'branch': branch_name, 'pushed_to_remote': pushed_to_remote, 'message': f"Successfully created local branch '{branch_name}'"}
    except Exception as e:
        return {'status': 'FAILED', 'error': str(e)}