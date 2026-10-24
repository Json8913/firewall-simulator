# Firewall Simulator

A small Python program that evaluates synthetic traffic against an ordered set of firewall rules and prints an auditable allow or deny decision.

**Stage:** Initial prototype.

## Scope and safety

This is a simulator only. It does not change operating-system firewall settings, send traffic, or protect a real host. The included addresses and packets are sample data.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Usage

    python3 firewall_simulator.py

Rules are evaluated from top to bottom. The first matching rule decides the outcome; traffic that matches no rule is denied by default.

## Findings

The sample demonstrates why rule ordering and a default-deny policy matter. Each decision includes the rule reason so the result can be reviewed.

## Current limits and next steps

The prototype uses hard-coded rules and packets. Next steps include loading a validated rules file, adding input validation, and showing the decision path for each packet.

## Screenshots

Add a terminal screenshot of the sample decisions.
