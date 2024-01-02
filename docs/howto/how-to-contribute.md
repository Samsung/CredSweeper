# Contributing

Thank you for your interest in contributing to the CredSweeper tool!

The document covers the process for contributing to the CredSweeper code and documentation. Contributions may be as simple as typo corrections or as complex as new features.

1.  [Process for contributing](#process-for-contributing)
    1. [Repository structure](#repository-structure)
    1. [File Name](#file-name)
    1. [Self Test & Verification](#self-test-and-verification)
1.  [How to PR](#how-to-pr)
1.  [DOs and DON'Ts](#dos-and-donts)


## Process for contributing

You need a basic understanding of [Git and GitHub.com](https://guides.github.com/activities/hello-world/).

**Step 1:** You can skip this step for small changes such as typo corrections. Open an [new issue](https://github.com/Samsung/CredSweeper/issues/new) describing what you want to do, such as change an existing code, functionality or create a new one.

You can also look at our [issues](https://github.com/Samsung/CredSweeper/issues) list and volunteer to work on the ones you're interested in.

**Step 2:** Fork the `/Samsung/CredSweeper` repo and create a branch for your changes.

For small changes, you can use GitHub's web interface. Simply click the **Edit the file in your fork of this project** on the file you'd like to change.
GitHub creates the new branch for you when you submit the changes.
VCS(git) requirement: the branch MUST be forked after latest release.

**Step 3:** Make the changes on this new branch.

Be sure to follow the proper Python syntax. For more information, see the [style guide](https://github.com/google/styleguide/blob/gh-pages/pyguide.md).
Use pre-commit hook with [yapf config file](https://github.com/Samsung/CredSweeper/blob/main/.style.yapf).


### Repository structure

All new filters or another feature should be located in the appropriate directories. Also, for all new functionality, you need to create new positive and negative tests in the appropriate file and directory in ./tests/

### File name

File names use the following rules:
- Contain only lowercase letters, numbers, and underlines.
- No spaces or punctuation characters. Use the underlines to separate words and numbers in the file name.
- Use action verbs that are specific, such as develop, buy, build, troubleshoot. No -ing words.
- No small words - don't include a, and, the, in, or, etc.
- Keep file names reasonably short.

### Self Test and Verification

After updating CredSweeper code, please verify your change doesn't break the library. We suggest unit-tests using the pytest. You can easily run it with:
   ```bash
   python -m pytest
   ```

Please make it sure running all tests and no any fail case.

**Step 4:** Submit a Pull Request (PR) from your branch to `Samsung/CredSweeper/master`.

Each PR should usually address one issue at a time. The PR can modify one or multiple files. If you're addressing multiple fixes on different files, separate PRs are preferred.

If your PR is addressing an existing issue, add the `Fixes #Issue_Number` keyword to the commit message or PR description. That way, the issue is automatically closed when the PR is merged. For more information, see [Closing issues via commit messages](https://help.github.com/articles/closing-issues-via-commit-messages/).

The CredSweeper team will review your PR and let you know if there are any other updates/changes necessary in order to approve it.

**Step 5:** Make any necessary updates to your branch as discussed with the team.

The maintainers will merge your PR into the master branch once feedback has been applied and your change is approved.


### How to PR

1. Fork form the original repository, https://github.com/Samsung/CredSweeper.
   (Ref. https://help.github.com/articles/fork-a-repo/)

2. Type `git clone`, and then paste the URL you copied in 1. It will look like this, with your GitHub username instead of `YOUR-USERNAME`:

   ```bash
   git clone https://github.com/YOUR-USERNAME/CredSweeper.git
   ```
3. Set to synchronize the original repository and the forked repository.

   ```bash
   git remote -v
   git remote add upstream https://github.com/Samsung/CredSweeper.git
   git remote -v
   ```
4. Create a new branch on the forked repository or the local repository,
   and switch to the new branch.

   ```bash
   git checkout -b <new branch name>
   ```
5. Install Yapf as a pre-commit hook with

   ``` bash
   pip install pre-commit
   pre-commit install
   ```
6. Create a local commit.

   ```bash
   git status
   git add
   git commit -a
   ```
7. Push the branch

   ```bash
   git push origin <new branch name>
   ```
8. Open a pull request on https://github.com/Samsung/CredSweeper.

    All tests and checks MUST be passed.
   - Codestyle check
   - Static analysis
   - Unit tests
     > - Development tests - use only linux and compatible version of packages. Code coverage is checked without test_app.py.
     > - Release tests - use Linux, Mac, Windows platform without version limitation.
   - Dynamic analysis (fuzzing)
     > Used Atheris framework to fuzzing various input. Code coverage is checked. In case of unsatisfied coverage - need to do new fuzzing or refactor fuzzer.  
   - Benchmark
     > If your PR changes benchmark scores - the scores MUST be updated (cicd/benchmark.txt)
   
9. Verify ActionTest after merge.
    > The test verifies integration CredSweeper to github action and points to main branch of main repo.

## DOs and DON'Ts

The following list shows some guiding rules that you should keep in mind when you're contributing to the CredSweeper:

- **DON'T** surprise us with large pull requests. Instead, file an issue and start a discussion so we can agree on a direction before you invest a large amount of time.
- **DO** read the [style guide](https://github.com/google/styleguide/blob/gh-pages/pyguide.md) guideline.
- **DO** create a separate branch on your fork before working on the changes.
- **DO** follow the [GitHub Flow workflow](https://guides.github.com/introduction/flow/).
- **DO** blog and tweet (or whatever) about your contributions, frequently!

> **Note**
>
> you might notice that some of the topics are not currently following all the guidelines specified here and on the [style guide](https://github.com/google/styleguide/blob/gh-pages/pyguide.md) as well. We're working towards achieving consistency throughout the tool. Check the list of [open issues](https://github.com/Samsung/CredSweeper/issues?q=is%3Aissue+is%3Aopen) we're currently tracking for that specific goal.
