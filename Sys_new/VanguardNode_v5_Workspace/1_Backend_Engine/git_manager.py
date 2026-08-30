import git
import os
from datetime import datetime

def create_remediation_pr(repo_path: str, scan_id: str, compliance_score: int):
    try:
        # 1. Resolve path and ensure directory exists
        abs_path = os.path.abspath(repo_path)
        if not os.path.exists(abs_path):
            return {"status": "FAILED", "error": f"Path does not exist: {abs_path}"}

        # 2. Auto-initialize Git repo if target folder isn't a repo yet
        try:
            repo = git.Repo(abs_path)
        except git.exc.InvalidGitRepositoryError:
            repo = git.Repo.init(abs_path)

        # 3. Ensure initial commit exists (fixes Unborn Branch error on empty local folders)
        if not repo.heads:
            readme_path = os.path.join(abs_path, "README.md")
            if not os.path.exists(readme_path):
                with open(readme_path, "w") as f:
                    f.write("# Vanguard Security Remediation\n")
            repo.index.add(["README.md"])
            repo.index.commit("Initial commit by Vanguard Engine")

        # 4. Generate unique branch name and checkout safely off a stable base
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        clean_scan_id = scan_id.replace(" ", "_") if scan_id else "manual"
        branch_name = f"security/vanguard-remediation-{clean_scan_id}-{timestamp}"

        # Try to branch off main/master if they exist, otherwise use current head
        base_ref = None
        if "main" in repo.heads:
            base_ref = repo.heads.main
        elif "master" in repo.heads:
            base_ref = repo.heads.master
        else:
            base_ref = repo.head.reference

        new_branch = repo.create_head(branch_name, commit=base_ref)
        new_branch.checkout()

        # 5. Stage untracked and modified files
        repo.git.add(A=True)

        # 6. Commit only if there are changes staged
        if repo.is_dirty(untracked_files=True):
            commit_message = (
                f"SecOps: Automated Remediation for {clean_scan_id}\n\n"
                f"Compliance Score: {compliance_score}%"
            )
            repo.index.commit(commit_message)

        # 7. Safely attempt remote push (Skip if no 'origin' remote exists)
        pushed_to_remote = False
        if "origin" in [remote.name for remote in repo.remotes]:
            try:
                origin = repo.remote(name="origin")
                origin.push(branch_name)
                pushed_to_remote = True
            except Exception as push_err:
                # Log push warning without failing the local branch creation
                print(f"[Warning] Remote push skipped/failed: {push_err}")

        return {
            "status": "SUCCESS",
            "branch": branch_name,
            "pushed_to_remote": pushed_to_remote,
            "message": f"Successfully created local branch '{branch_name}'"
        }

    except Exception as e:
        return {"status": "FAILED", "error": str(e)}