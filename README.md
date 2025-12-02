# GitBlitSecCheck
## Install
generate with ant the ZIP-File GitBlitSecCheck.zip and plase it in the gitblit plugin directoy.<br>
If there is no *etc/gitleaks.toml* an fresh is once fetched from:<br>
https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml<br>
Another one could be downloaded from<br>
https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules/-/packages<br>
Currently the files must be placed in **etc/gitleaks.toml**


## Sample with an test secret in the .gitignore file.*

```
>git commit -m "X" .gitignore & git push
[master 3eb1b1d] X
 1 file changed, 1 insertion(+)
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 300 bytes | 300.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (1/1)
To https://fqdn/git/r/repro.git
 ! [remote rejected] master -> master (
Found possible secret [LTAI01234567890123456789] via rule [generic-api-key] in file [.gitignore])
error: failed to push some refs to 'https://fqdn/git/r/repro.git'

```