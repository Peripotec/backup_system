import os
import subprocess
from settings import REPO_DIR
from core.logger import log

class GitManager:
    def __init__(self, repo_dir=REPO_DIR):
        self.repo_dir = repo_dir
        self._ensure_repo()

    def _run_git(self, args, cwd=None):
        """Helper to run git commands."""
        if not cwd:
            cwd = self.repo_dir
        
        try:
            # Use full path to git to avoid PATH issues with systemd
            git_path = "/usr/bin/git"
            cmd = [git_path] + args
            result = subprocess.run(
                cmd, 
                cwd=cwd, 
                capture_output=True, 
                text=True, 
                check=True,
                encoding='utf-8', 
                errors='replace' # Handle potential encoding issues
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            log.error(f"Git command failed: {' '.join(cmd)}")
            log.error(f"Error: {e.stderr}")
            return None
        except FileNotFoundError:
            log.error("Git is not installed or not in PATH.")
            return None

    def _ensure_repo(self):
        """Initializes the git repo if it doesn't exist."""
        if not os.path.exists(self.repo_dir):
            try:
                os.makedirs(self.repo_dir, exist_ok=True)
                log.info(f"Initializing Git repo at {self.repo_dir}")
                self._run_git(["init"], cwd=self.repo_dir)
                # Config user if needed (local to this repo)
                self._run_git(["config", "user.name", "Backup System"], cwd=self.repo_dir)
                self._run_git(["config", "user.email", "backup@system.local"], cwd=self.repo_dir)
            except Exception as e:
                log.error(f"Failed to initialize repo: {e}")

    def commit_file(self, file_path, hostname, vendor):
        """
        Adds and commits a specific file.
        Returns True if changes were committed, False otherwise (no changes or validation error).
        """
        if not os.path.exists(file_path):
            log.warning(f"File not found for commit: {file_path}")
            return False

        # Make path relative to repo root for git commands
        rel_path = os.path.relpath(file_path, self.repo_dir)

        # Allow empty commits? No.
        # Check status first
        status = self._run_git(["status", "--porcelain", rel_path])
        if not status:
            log.debug(f"No changes detected for {hostname}")
            return False

        self._run_git(["add", rel_path])
        msg = f"Backup {vendor}/{hostname}"
        self._run_git(["commit", "-m", msg])
        log.info(f"Committed changes for {hostname}")
        return True

    def get_diff(self, file_path):
        """
        Returns the diff of the last commit for this file.
        """
        rel_path = os.path.relpath(file_path, self.repo_dir)
        # git show HEAD:path/to/file vs previous?
        # Or just git show for the last commit involving this file?
        
        # Simple approach: git log -p -1 -- path
        return self._run_git(["log", "-p", "-1", "--pretty=format:", "--", rel_path])
