# git操作手册

## 从远程主机克隆一个版本库
```bash
git clone git@120.76.136.83:onlinecourse.git

```

## 查看分支
1. 查看远程分支

```bash
cd onlinecourse
git branch -r

```

2. 查看本地分支

```bash
git branch

```

## 从远端下载新的分支到本地分支(-b 创建)
1. git checkout -b 本地分支 远端分支

```bash
git checkout -b feature-8.7-Preview origin/feature-8.7-Preview
```

2. 创建自己的分支(在此分支进行每天的开发)
```bash
git checkout -b feature-8.7-Preview
```

3. 分支命名的规则

* feature-日期-特性(首字母大写，用And连接特性)
* feature-8.7-Feature1AndFeature2AndFeature


## 修改分支名称
```bash
git branch -m 旧分支名 新分支名
```


## 删除分支
```bash
git branch -d 分支名
git branch -D #强制删除
```


## 提交新修改的东西：
```bash
git add new_file                              #添加新文件到git
git add ./*                                   #这样也是可以的
git commit -am "说明文字，简短，字数有限"
git push [origin 本地分支名:远端新分支名]     #第一次提交，需要设置origin
```

## 从仓库中移除文件或目录
```bash
git rm -r ./.idea/* --cached    # 建议：加上cached不会删除文件，只是从repos中移除
git rm ./.gradle                # -r 是递归移除，用于目录
#删除完，然后再提交一遍
```

## 查看提交日志
```bash
git log
```

## 回退以前某个提交
```
git reset hash   #从git log中可以查看到commit的hash
```
