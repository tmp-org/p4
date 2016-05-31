#!/usr/bin/env python
import os
import re
import yaml
from github import Github
import sqlite3
import datetime
from dateutil import parser as dtp
import parsedatetime
import argparse
import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()
logging.getLogger('github').setLevel(logging.INFO)

gh = Github(
    login_or_token=os.environ.get('GITHUB_USERNAME', None) or os.environ.get('GITHUB_OAUTH_TOKEN', None),
    password=os.environ.get('GITHUB_PASSWORD', None),
)

log.warn("GH API RATE LIMIT: %s/%s" % gh.rate_limiting)


UPVOTE_REGEX = '(:\+1:|^\s*\+1\s*$)'
DOWNVOTE_REGEX = '(:\-1:|^\s*\-1\s*$)'


class PullRequestFilter(object):

    def __init__(self, name, conditions, actions, committer_group=None,
                 bot_user=None, dry_run=False, next_milestone=None, repo=None):
        self.name = name
        self.conditions = conditions
        self.actions = actions
        self.committer_group = [] if committer_group is None else committer_group
        self.repo = repo
        self.bot_user = bot_user
        self.dry_run = dry_run
        self.next_milestone = next_milestone
        log.info("Registered PullRequestFilter %s", name)

    def _condition_it(self):
        for condition_dict in self.conditions:
            for key in condition_dict:
                yield (key, condition_dict[key])

    def apply(self, pr):
        """Apply a given PRF to a given PR. Causes all appropriate conditions
        to be evaluated for a PR, and then the appropriate actions to be
        executed
        """
        log.debug("\t[%s]", self.name)
        try:
            self.issue = self.repo.get_issue(pr.number)
        except Exception, e:
            log.warn("Could not access issue")
            log.warn(e)
            return False

        for (condition_key, condition_value) in self._condition_it():
            res = self.evaluate(pr, condition_key, condition_value)
            log.debug("\t\t%s, %s => %s", condition_key, condition_value, res)

            if not res:
                return True

        log.info("Matched %s", pr.number)
        # If we've made it this far, we pass ALL conditions
        for action in self.actions:
            self.execute(pr, action)

        return True

    def _time_to_int(self, result, condition_value):
        # Times we shoe-horn into numeric types.
        # Since condition_value is a string, we have to have some special
        # logic for correcting it into a time
        (date_type, date_string) = condition_value.split('::', 1)
        if date_type == 'relative':
            # Get the current time, adjusted for strings like "168
            # hours ago"
            current = datetime.datetime.now()
            calendar = parsedatetime.Calendar()
            compare_against, parsed_as = calendar.parseDT(date_string, current)
        elif date_type == 'precise':
            compare_against = dtp.parse(date_string)
        else:
            raise Exception("Unknown date string type. Please use 'precise::2016-01-01' or 'relative::yesterday'")

        # Now we update the result to be the total number of seconds
        result = (result - compare_against).total_seconds()
        # And condition value to zero
        condition_value = 0
        # As a result, all of the math in evaluate() works.
        return result, condition_value

    def evaluate(self, pr, condition_key, condition_value):
        """Evaluate a condition like "title_contains" or "plus__ge".

        The condition_key maps to a function such as "check_title_contains" or "check_plus"
        If there is a '__X' that maps to a comparator function which is
        then used to evlauate the result.
        """

        # Some conditions contain an aditional operation we must respect, e.g.
        # __gt or __eq
        if '__' in condition_key:
            (condition_key, condition_op) = condition_key.split('__', 1)
        else:
            condition_op = None

        func = getattr(self, 'check_' + condition_key)
        result = func(pr, cv=condition_value)

        if condition_key == 'created_at':
            result, condition_value = self._time_to_int(result, condition_value)

        # There are two types of conditions, text and numeric.
        # Numeric conditions are only appropriate for the following types:
        # 1) plus, 2) minus, 3) times which were hacked in
        if condition_key in ('plus', 'minus', 'created_at', 'tag_count'):
            if condition_op == 'gt':
                return int(result) > int(condition_value)
            elif condition_op == 'ge':
                return int(result) >= int(condition_value)
            elif condition_op == 'eq':
                return int(result) == int(condition_value)
            elif condition_op == 'ne':
                return int(result) != int(condition_value)
            elif condition_op == 'lt':
                return int(result) < int(condition_value)
            elif condition_op == 'le':
                return int(result) <= int(condition_value)
        # Then there are the next set of tpyes which are mostly text types
        else:
            # These have generally already been evaluated by the function, we
            # just return value/!value
            if condition_op == 'not':
                return not result
            else:
                return result

    def check_title_contains(self, pr, cv=None):
        """condition_value in pr.title
        """
        return cv in pr.title

    def check_milestone(self, pr, cv=None):
        """condition_value == pr.milestone
        """
        return pr.milestone == cv

    def check_state(self, pr, cv=None):
        """checks if state == one of cv in (open, closed, merged)
        """
        if cv == 'merged':
            return pr.merged
        else:
            return pr.state == cv

    def _find_in_comments(self, pr, regex):
        """Search for hits to a regex in a list of comments
        """
        if getattr(pr, 'memo_comments', None) is None:
            pr.memo_comments = list(self.issue.get_comments())

        for comment in pr.memo_comments:
            # log.debug('%s, "%s" => %s', regex, comment.body, re.match(regex, comment.body))
            if re.findall(regex, comment.body, re.MULTILINE):
                yield comment

    def check_plus(self, pr, cv=None):
        count = 0
        for plus1_comment in self._find_in_comments(pr, UPVOTE_REGEX):
            if plus1_comment.user.login in self.committer_group:
                count += 1

        return count

    def check_tag_count(self, pr, cv=None):
        """Checks number of tags
        """
        count = 0
        m = re.compile(cv)
        issue = self.repo.get_issue(pr.number)
        for label in issue.get_labels():
            count += 1
        return count

    def check_has_tag(self, pr, cv=None):
        """Checks that at least one tag matches the regex provided in condition_value
        """
        # Tags aren't actually listed in the PR, we have to fetch the issue for that
        m = re.compile(cv)
        issue = self.repo.get_issue(pr.number)
        for label in issue.get_labels():
            if m.match(label.name):
                return True

        return False

    def check_minus(self, pr, cv=None):
        count = 0
        for minus1_comment in self._find_in_comments(pr, DOWNVOTE_REGEX):
            if minus1_comment.user.login in self.committer_group:
                count += 1

        return count

    def check_to_branch(self, pr, cv=None):
        return pr.base.ref == cv

    def check_created_at(self, pr, cv=None):
        """Due to condition_values with times, check_created_at simply returns pr.created_at

        Other math must be done to correctly check time. See _time_to_int
        """
        return pr.created_at

    def execute(self, pr, action):
        """Execute an action by name.
        """
        log.info("Executing action")
        if self.dry_run:
            return

        func = getattr(self, 'execute_' + action['action'])
        return func(pr, action)

    def execute_comment(self, pr, action):
        """Commenting action, generates a comment on the parent PR
        """
        comment_text = action['comment'].format(
            author='@' + pr.user.login
            # TODO
            # merged_by=
        ).strip().replace('\n', ' ')

        # Check if we've made this exact comment before, so we don't comment
        # multiple times and annoy people.
        for possible_bot_comment in self._find_in_comments(pr, comment_text):

            if possible_bot_comment.user.login == self.bot_user:
                log.info("Comment action previously applied, not duplicating")
            else:
                log.info("Comment action previously applied, not duplicating. However it was applied under a different user. Strange?")

            return

        # Create the comment
        self.issue.create_comment(
            comment_text
        )

    def execute_assign_next_milestone(self, pr, action):
        """Assigns a pr's milestone to next_milestone
        """
        # Can only update milestone through associated PR issue.
        self.issue.edit(milestone=self.next_milestone)

    def execute_remove_tag(self, pr, action):
        """Tags a PR
        """
        tag_name = action['action_value']
        self.issue.remove_from_labels(tag_name)

    def execute_assign_tag(self, pr, action):
        """Tags a PR
        """
        tag_name = action['action_value']
        self.issue.add_to_labels(tag_name)

    def execute_remove_tag(self, pr, action):
        """remove a tag from PR if it matches the regex
        """
        m = re.compile(action['action_value'])
        for label in self.issue.get_labels():
            if m.match(label.name):
                self.issue.remove_from_labels(label.name)


class MergerBot(object):

    def __init__(self, conf_path, dry_run=False):
        self.dry_run = dry_run
        with open(conf_path, 'r') as handle:
            self.config = yaml.load(handle)

        self.create_db(database_name=os.path.abspath(
            self.config['meta']['database_path']))

        self.timefmt = "%Y-%m-%dT%H:%M:%S.Z"

        self.repo_owner = self.config['repository']['owner']
        self.repo_name = self.config['repository']['name']
        self.repo = gh.get_repo(self.repo_owner + '/' + self.repo_name)

        self.pr_filters = []
        self.next_milestone = [
            milestone for milestone in self.repo.get_milestones() if
            milestone.title == self.config['repository']['next_milestone']][0]

        for rule in self.config['repository']['filters']:
            prf = PullRequestFilter(
                name=rule['name'],
                conditions=rule['conditions'],
                actions=rule['actions'],
                next_milestone=self.next_milestone,
                repo=self.repo,
                committer_group=self.config['repository']['pr_approvers'],
                bot_user=self.config['meta']['bot_user'],
                dry_run=self.dry_run,
            )
            self.pr_filters.append(prf)

    def create_db(self, database_name='cache.sqlite'):
        """Create the database if it doesn't exist"""
        self.conn = sqlite3.connect(database_name)
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS pr_data(
                pr_id INTEGER PRIMARY KEY,
                updated_at TEXT
            )
            """
        )

    def fetch_pr_from_db(self, id):
        """select PR from database cache by PR #"""
        cursor = self.conn.cursor()
        cursor.execute("""SELECT * FROM pr_data WHERE pr_id == ?""", (str(id), ))
        row = cursor.fetchone()

        if row is None:
            return row

        pretty_row = (
            row[0],
            datetime.datetime.strptime(row[1], self.timefmt)
        )
        return pretty_row

    def cache_pr(self, id, updated_at):
        """Store the PR in the DB cache, along with the last-updated
        date"""
        cursor = self.conn.cursor()
        cursor.execute("""INSERT INTO pr_data VALUES (?, ?)""",
                       (str(id), updated_at.strftime(self.timefmt)))
        self.conn.commit()

    def update_pr(self, id, updated_at):
        """Update the PR date in the cache"""
        if self.dry_run:
            return
        cursor = self.conn.cursor()
        cursor.execute("""UPDATE pr_data SET updated_at = ? where pr_id = ?""",
                       (updated_at.strftime(self.timefmt), str(id)))
        self.conn.commit()

    def all_prs(self):
        """List all open PRs in the repo.

        This... needs work. As it is it fetches EVERY PR, open and closed
        and that's a monotonically increasing number of API requests per
        run. Suboptimal.
        """
        log.info("Locating closed PRs")
        results = self.repo.get_pulls(state='closed')
        for i, result in enumerate(results):
            yield result

        log.info("Locating open PRs")
        results = self.repo.get_pulls(state='open')
        for result in results:
            yield result

    def get_modified_prs(self):
        """This will contain a list of all new/updated PRs to filter
        """
        changed_prs = []
        # Loop across our GH results
        for resource in self.all_prs():
            # Fetch the PR's ID which we use as a key in our db.
            cached_pr = self.fetch_pr_from_db(resource.id)
            # If it's new, cache it.
            if cached_pr is None:
                self.cache_pr(resource.id, resource.updated_at)
                changed_prs.append(resource)
            else:
                # compare updated_at times.
                cached_pr_time = cached_pr[1]
                if cached_pr_time != resource.updated_at:
                    log.debug('[%s] Cache says: %s last updated at %s', resource.number, cached_pr_time, resource.updated_at)
                    changed_prs.append(resource)
        return changed_prs

    def run(self):
        """Find modified PRs, apply the PR filter, and execute associated
        actions"""
        changed_prs = self.get_modified_prs()
        log.info("Found %s PRs to examine", len(changed_prs))
        for changed in changed_prs:

            log.debug("Evaluating %s", changed.number)
            for pr_filter in self.pr_filters:
                success = pr_filter.apply(changed)
                if success and not self.dry_run:
                    # Otherwise we'll hit it again later
                    self.update_pr(changed.id, changed.updated_at)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4 bot')
    parser.add_argument('--dry-run', dest='dry_run', action='store_true')
    args = parser.parse_args()

    bot = MergerBot('conf.yaml', **vars(args))
    bot.run()
