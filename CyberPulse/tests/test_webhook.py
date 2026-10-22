"""
Unit tests for Webhook Dispatcher module.
Verifies payload formats for Discord, Slack, and Microsoft Teams.
"""
import unittest
from modules.webhook import (
    detect_webhook_platform,
    format_discord_payload,
    format_slack_payload,
    format_teams_payload,
    dispatch_webhook_alert
)


class TestWebhookDispatcher(unittest.TestCase):

    def test_platform_detection(self):
        discord_url = "https://discord.com/api/webhooks/12345/abcdef"
        slack_url = "https://hooks.slack.com/services/T00/B00/XXXX"
        teams_url = "https://example.office.com/webhook/1234"
        other_url = "https://custom-siem.local/alert"

        self.assertEqual(detect_webhook_platform(discord_url), "discord")
        self.assertEqual(detect_webhook_platform(slack_url), "slack")
        self.assertEqual(detect_webhook_platform(teams_url), "teams")
        self.assertEqual(detect_webhook_platform(other_url), "generic")

    def test_discord_payload_formatting(self):
        risk = {"score": 92, "level": "Malicious / Critical", "color": "#ef4444", "actions": ["Block IP"]}
        otx = {"malware_families": ["Cobalt Strike"], "pulse_count": 5}
        payload = format_discord_payload("185.220.101.5", "IPV4", risk, {}, otx)

        self.assertIn("embeds", payload)
        embed = payload["embeds"][0]
        self.assertIn("185[.]220[.]101[.]5", embed["title"])
        self.assertEqual(embed["color"], 0xef4444)
        field_names = [f["name"] for f in embed["fields"]]
        self.assertIn("Malware Families", field_names)

    def test_slack_payload_formatting(self):
        risk = {"score": 50, "level": "Suspicious / Moderate", "color": "#f59e0b"}
        payload = format_slack_payload("evil-domain.com", "DOMAIN", risk)
        self.assertIn("attachments", payload)
        self.assertEqual(payload["attachments"][0]["color"], "#f59e0b")

    def test_teams_payload_formatting(self):
        risk = {"score": 10, "level": "Benign", "color": "#10b981"}
        payload = format_teams_payload("8.8.8.8", "IPV4", risk)
        self.assertEqual(payload["@type"], "MessageCard")
        self.assertEqual(payload["themeColor"], "10b981")

    def test_dry_run_dispatch(self):
        risk = {"score": 85, "level": "High", "color": "#ef4444"}
        res = dispatch_webhook_alert("https://discord.com/api/webhooks/dummy", "1.2.3.4", "IPV4", risk, dry_run=True)
        self.assertTrue(res["success"])
        self.assertTrue(res["simulated"])
        self.assertEqual(res["platform"], "discord")

    def test_null_actions_and_malware_resilience(self):
        risk = {"score": 90, "level": "Malicious", "color": "#ef4444", "actions": None}
        otx = {"malware_families": None, "pulse_count": None}
        vt = {"malicious": None}

        d_pay = format_discord_payload("1.2.3.4", "IPV4", risk, vt, otx)
        self.assertIn("embeds", d_pay)

        s_pay = format_slack_payload("1.2.3.4", "IPV4", risk, vt, otx)
        self.assertIn("attachments", s_pay)

        t_pay = format_teams_payload("1.2.3.4", "IPV4", risk, vt, otx)
        self.assertEqual(t_pay["@type"], "MessageCard")


if __name__ == "__main__":
    unittest.main()

