import logging
import os
import sys
import hmac
import json

from flask import Flask, redirect, request
from flask_session import Session
from flask import abort
from flask import Response as FResponse
from jira import JIRA

global rh_jira

def Response(data=None, status=200, mimetype='application/json'):
    if data is None:
        data = {}

    response_object = json.dumps(data, default=lambda obj: obj.__dict__)
    return FResponse(response_object, status=status, mimetype=mimetype)

def match_webhook_secret(request):
    """Match the webhook secret sent from GitHub"""
    if ('X-Hub-Signature' in request.headers and
        request.headers.get('X-Hub-Signature') is not None):
        header_signature = request.headers.get('X-Hub-Signature', None)
    else:
        abort(403)
    sha_name, signature = header_signature.split('=')
    if sha_name != 'sha1':
        abort(501)

    mac = hmac.new(os.environ["GITHUB_WEBHOOK_SECRET"].encode(),
                    msg=request.data,
                    digestmod="sha1")

    if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
        abort(403)
    return True

def handle_unauthorized_requests():
    response_object = {
        "message": "Unauthorized request"
    }
    return Response(response_object, 401)


def handle_pull_request(request_json):
    response_object = {
        "message": "Authorized request"
    }
    try:
        pr_body = request_json['pull_request']['body']
    except:
        response_object['message'] = "Pull request JSON is missing required key 'body'"
        return Response(response_object, 400)

    try:
        pr_url = request_json['pull_request']['html_url']
    except:
        response_object['message'] = "Pull request JSON is missing required key 'url'"
        return Response(response_object, 400)

    pr_body = pr_body.lower()
    if not "jira" in pr_body:
        response_object['message'] = "Pull request JSON is missing Jira keyword"
        return Response(response_object, 400)

    pr_lines = pr_body.splitlines()
    for line in pr_lines:
        if "jira" in line:
            jira_issue_id = line.split(":")[1].strip()
    
    if jira_issue_id == "":
        response_object['message'] = "Pull request JSON is missing Jira issue"
        return Response(response_object, 400)

    app.logger.debug(f"PR body:\n{pr_body}")
    app.logger.debug(f"Jira issue:{jira_issue_id}")

    # Get the Jira issue mentioned in the PR
    try:
        issue = rh_jira.issue(jira_issue_id, fields='summary,comment')
    except:
        response_object['message'] = "Invalid Jira issue ID"
        return Response(response_object, 400)

    app.logger.debug(f"Jira issue:{issue.fields.summary}")

    # Check if the PR URL is already referenced in a Jira comment
    comments = issue.fields.comment.comments
    pr_url_found = False
    for comment in comments:
        if pr_url in comment.body:
            pr_url_found = True
            break
    # Check if the state of the PR is open or updated and if the PR has WIP label then transition the Jira story to
    # "In Progress". If the state of PR is closed then we mark the story as done.
    # Get the PR state
    try:
        pr_state = request_json['action']
    except:
        response_object['message'] = "Pull request JSON doesn't contain key 'action'"
        return Response(response_object, 400)

    app.logger.debug(f"PR state:{pr_state}")
    # Get PR labels
    wip_label = 'do-not-merge/work-in-progress'
    lgtm_label ='lgtm'
    approved_label = 'approved'
    # TODO: Check for edited state
    in_progress_or_ci_state_triggers = ["opened", "reopened", "edited", "labeled", "unlabeled"]

    try:
        pr_labels = request_json['pull_request']['labels']
    except:
        response_object['message'] = "Pull request contain doesn't contain key 'labels'"
        return Response(response_object, 400)

    has_lgtm_label = False
    has_approved_label = False
    has_wip_label = False
    for pr_label in pr_labels:
        app.logger.debug(f"PR label:{pr_label['name']}")
        if pr_state in in_progress_or_ci_state_triggers:
            if pr_label['name'] == wip_label:
                has_wip_label = True
                # Transition Jira story to In progress
                rh_jira.transition_issue(issue, "In Progress")
                app.logger.debug(f"Transitioned to in progress")
            if pr_label['name'] == lgtm_label:
                app.logger.debug(f"Found lgtm")
                has_lgtm_label = True
            if pr_label['name'] == approved_label:
                app.logger.debug(f"Found approved")
                has_approved_label = True
    if has_approved_label and has_lgtm_label:
        app.logger.debug(f"Transition to pending CI")
        try:
            rh_jira.transition_issue(issue, "Pending CI")
            app.logger.debug(f"Transitioned to pending ci")
        except:
            response_object['message'] = "Jira transition failed"
            return Response(response_object, 400)
    elif not has_wip_label:
        app.logger.debug(f"Transition to code review")
        try:
            rh_jira.transition_issue(issue, "Code Review")
            app.logger.debug(f"Transitioned to pending ci")
        except:
            response_object['message'] = "Jira transition failed"
            return Response(response_object, 400)
    # Add the PR URL as a comment in the Jira issue
    if not pr_url_found:
        try:
            rh_jira.add_comment(issue, pr_url)
        except:
            response_object['message'] = "Error updating Jira issue"
            return Response(response_object, 400)

    return Response(response_object, 200)


def create_app():
    app = Flask(__name__)
    sess = Session()

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    @app.route("/event_handler", methods=['GET', 'POST'])
    def main():
        """Main function to handle all requests."""
        if request.method == "POST":
            # GitHub sends the secret key in the payload header
            if match_webhook_secret(request):
                event = request.headers["X-GitHub-Event"]
                event_to_action = {
                    "pull_request": handle_pull_request
                }
                supported_event = event in event_to_action
                if supported_event:
                    return event_to_action[event](request.json)
                else:
                    # TODO: replace with a more appropriate request
                    return handle_unauthorized_requests()

            else:
                app.logger.info("Received an unauthorized request")
                return handle_unauthorized_requests()
        else:
            return redirect("https://pep8speaks.com")

    app.secret_key = os.environ.setdefault("APP_SECRET_KEY", "")
    app.config['SESSION_TYPE'] = 'filesystem'

    sess.init_app(app)
    app.debug = False
    return app


app = create_app()

if __name__ == '__main__':
    rh_jira = JIRA(server='https://issues.redhat.com', auth=(os.environ["JIRA_USER"], os.environ["JIRA_PASSWORD"]))
    app.run(debug=True)
