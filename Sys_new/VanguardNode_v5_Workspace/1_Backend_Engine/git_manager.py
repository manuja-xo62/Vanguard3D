import git
from datetime import datetime

def create_remediation_pr(repo_path: str, scan_id: str, compliance_score: int):
    try:
        repo = git.Repo(repo_path)
        
        branch_name = f"vanguard-remediation-{scan_id}-{datetime.now().strftime('%Y%m%d%H%M')}"
        new_branch = repo.create_head(branch_name)
        new_branch.checkout()
        
        repo.git.add(update=True)
        commit_message = f"SecOps: Automated Remediation for {scan_id}\n\nCompliance Score: {compliance_score}%"
        repo.index.commit(commit_message)
        
        origin = repo.remote(name='origin')
        origin.push(branch_name)
        
        # A subsequent REST call to GitHub/GitLab API would go here to open the PR
        return {"status": "SUCCESS", "branch": branch_name}
    except Exception as e:
        return {"status": "FAILED", "error": str(e)}