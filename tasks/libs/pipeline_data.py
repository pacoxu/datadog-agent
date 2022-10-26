import re

from .common.gitlab import Gitlab, get_gitlab_token
from .types import FailedJobReason, FailedJobType


def get_failed_jobs(project_name, pipeline_id):
    """
    Retrieves the list of failed jobs for a given pipeline id in a given project.
    """

    gitlab = Gitlab(project_name=project_name, api_token=get_gitlab_token())

    # gitlab.all_jobs yields a generator, it needs to be converted to a list to be able to
    # go through it twice
    jobs = list(gitlab.all_jobs(pipeline_id))

    # Get instances of failed jobs
    failed_jobs = {job["name"]: [] for job in jobs if job["status"] == "failed"}

    # Group jobs per name
    for job in jobs:
        if job["name"] in failed_jobs:
            failed_jobs[job["name"]].append(job)

    # There, we now have the following map:
    # job name -> list of jobs with that name, including at least one failed job
    final_failed_jobs = []
    for job_name, jobs in failed_jobs.items():
        # We sort each list per creation date
        jobs.sort(key=lambda x: x["created_at"])
        # We truncate the job name to increase readability
        job_name = truncate_job_name(job_name)
        # Check the final job in the list: it contains the current status of the job
        # This excludes jobs that were retried and succeeded
        failure_type, failure_reason = get_job_failure_context(gitlab.job_log(jobs[-1]["id"]))
        final_status = {
            "name": job_name,
            "id": jobs[-1]["id"],
            "stage": jobs[-1]["stage"],
            "status": jobs[-1]["status"],
            "allow_failure": jobs[-1]["allow_failure"],
            "url": jobs[-1]["web_url"],
            "retry_summary": [job["status"] for job in jobs],
            "failure_type": failure_type,
            "failure_reason": failure_reason,
        }

        # Also exclude jobs allowed to fail
        if final_status["status"] == "failed" and not final_status["allow_failure"]:
            final_failed_jobs.append(final_status)

    return final_failed_jobs


infra_failure_logs = [
    # Gitlab errors while pulling image on legacy runners
    (re.compile(r'no basic auth credentials \(.*\)'), FailedJobReason.MAIN_RUNNER),
    (re.compile(r'net/http: TLS handshake timeout \(.*\)'), FailedJobReason.MAIN_RUNNER),
    (
        re.compile(r'Failed to pull image with policy "always": error pulling image configuration'),
        FailedJobReason.MAIN_RUNNER,
    ),
    # docker / docker-arm runner init failures
    (re.compile(r'Docker runner job start script failed'), FailedJobReason.DOCKER_RUNNER),
    (
        re.compile(
            r'A disposable runner accepted this job, while it shouldn\'t have\. Runners are meant to run just one job and be terminated\.'
        ),
        FailedJobReason.DOCKER_RUNNER,
    ),
    (
        re.compile(r'WARNING: Failed to pull image with policy "always":.*:.*\(.*\)'),
        FailedJobReason.DOCKER_RUNNER,
    ),
    # k8s Gitlab runner init failures
    (
        re.compile(
            r'Job failed \(system failure\): prepare environment: waiting for pod running: timed out waiting for pod to start'
        ),
        FailedJobReason.K8S_RUNNER,
    ),
    # kitchen tests Azure VM allocation failures
    (
        re.compile(
            r'Allocation failed\. We do not have sufficient capacity for the requested VM size in this region\.'
        ),
        FailedJobReason.KITCHEN_AZURE,
    ),
    # kitchen tests general infrastructure issues
    (
        re.compile(
            r'ERROR: The kitchen tests failed due to infrastructure failures\.'
        ),
        FailedJobReason.KITCHEN,
    )
]


def get_job_failure_context(job_log):
    """
    Parses job logs (provided as a string), and returns the type of failure (infra or job) as well
    as the precise reason why the job failed.
    """

    for regex, type in infra_failure_logs:
        if regex.search(job_log):
            return FailedJobType.INFRA_FAILURE, type
    return FailedJobType.JOB_FAILURE, FailedJobReason.FAILED_JOB_SCRIPT


def truncate_job_name(job_name, max_char_per_job=48):
    # Job header should be before the colon, if there is no colon this won't change job_name
    truncated_job_name = job_name.split(":")[0]
    # We also want to avoid it being too long
    truncated_job_name = truncated_job_name[:max_char_per_job]
    return truncated_job_name
