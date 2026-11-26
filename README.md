# Firewall Simulator

[![Checks](https://github.com/Json8913/firewall-simulator/actions/workflows/checks.yml/badge.svg?branch=main)](https://github.com/Json8913/firewall-simulator/actions/workflows/checks.yml)

A small Python program that evaluates synthetic traffic against an ordered set of firewall rules and prints an auditable allow or deny decision.

**Author:** Jason Santos Ritchie

**Stage:** Initial prototype with numbered rule traces.

## Scope and safety

This is a simulator only. It does not change operating-system firewall settings, send traffic, or protect a real host. The included addresses and packets are sample data.

## Requirements

- Python 3.10 or newer
- No third-party Python packages
- Tkinter for the desktop interface

## Desktop interface

Run the desktop app with:

    python3 gui.py

The window shows the ordered sample rules and a decision trace for the included synthetic packets. It does not change host firewall settings.

## Usage

    python3 firewall_simulator.py

Rules are evaluated from top to bottom. The first matching rule decides the outcome; traffic that matches no rule is denied by default. Each printed decision now identifies the matching rule number, or `default` when no rule matches.

## Smoke check

The sample allowed HTTPS from the trusted subnet, denied a blocked lab host, and denied traffic that matched no allow rule.

## Findings

The sample demonstrates why rule ordering and a default-deny policy matter. Each decision includes its reason and rule reference so the result can be reviewed against the configured rule list.

## Current limits and next steps

The prototype uses hard-coded rules and packets. Next steps include loading a rules file and validating its contents.

## Demo screenshot

![Firewall simulator sample decisions](screenshots/firewall-simulator-demo.png)

The example uses synthetic packets; it does not change host firewall settings.
