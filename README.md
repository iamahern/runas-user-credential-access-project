# runas-user-credential-access-project
Extends the Authorize Project Plugin to allow access to RunAs user Credentials.

This project borrows heavily from code from the [Authorize Project](https://github.com/jenkinsci/authorize-project-plugin) plugin.


# Background

This plugin was built out of a conversation regarding the Authorize
Project Plugin ([Jenkins-55052](https://issues.jenkins-ci.org/browse/JENKINS-55052)).

As a user, the ability to override the ability to override the
Credential plugin sandbox is extremely useful in certain cases. In our
case, we have a single tenanted Jenkins instance setup solely for
operations runbook automation. Being able to break the Credential's
plugin sandbox allows for the creation of Jobs which execute cloud
tasks as the user that clicked the run button on the job.

Without this plugin, Job operations engineers are forced to add 2-3
extra drop down's per job to expose private credentials OR require
users to place their credentials in global credential storage. Using
the plugin, jobs can be authorized to access user private settings by
hook-and-crook - simplifying the end user operations user experience.

From a security standpoint, the concerns over run-as user access involve
asynchronous user inputs to Jenkins jobs. If you do not have those and
you have a dedicated / restricted Jenkins instance for a narrow set
of user cases with controlled Job installation, you are likely fine.


# Problems Solved

This plugin solves the issues described [Jenkins 44772](https://issues.jenkins-ci.org/browse/JENKINS-44772).

```
node {
    // verify that the build is properly impersonated by the https://wiki.jenkins-ci.org/display/JENKINS/Authorize+Project+plugin
    echo "Build is running as user " + org.acegisecurity.context.SecurityContextHolder.getContext().getAuthentication().toString()

    stage ("User Scoped Credentials") {
        withCredentials([
            usernamePassword(
                credentialsId: 'my-username-password',
                passwordVariable: 'PASSWORD_VAR',
                usernameVariable: 'USERNAME_VAR')]) {
           sh "echo $PASSWORD_VAR > spy-user-scoped-credentials.txt"
        }
    }
}
```


# Limitations & Work Arounds

The one **oddity** is that a Credential Parameters for jobs will only
show the user's personal credentials - omitting and global or folder
credentials.

While they are missing from the drop down, they can still be used within
the job. Thus, simply have a front-end job with the authorization
plugin disabled call a second job with the plugin enabled.
