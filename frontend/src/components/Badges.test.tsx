import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ActionBadge, InjectionBadge, RiskBadge, RiskScoreBar } from "./Badges";

describe("Badges", () => {
  it("renders the risk level text", () => {
    render(<RiskBadge level="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  it("renders BLOCKED action distinctly", () => {
    render(<ActionBadge action="BLOCKED" />);
    expect(screen.getByText("BLOCKED")).toBeInTheDocument();
  });

  it("renders APPROVAL_REQUIRED with a space, not an underscore", () => {
    render(<ActionBadge action="APPROVAL_REQUIRED" />);
    expect(screen.getByText("APPROVAL REQUIRED")).toBeInTheDocument();
  });

  it("renders the injection classification", () => {
    render(<InjectionBadge classification="MALICIOUS" />);
    expect(screen.getByText("MALICIOUS")).toBeInTheDocument();
  });

  it("renders the numeric risk score rounded", () => {
    render(<RiskScoreBar score={83.6} level="HIGH" />);
    expect(screen.getByText("84")).toBeInTheDocument();
  });

  it("clamps the score bar width to 100% even if score exceeds 100", () => {
    const { container } = render(<RiskScoreBar score={150} level="CRITICAL" />);
    const bar = container.querySelector("div.rounded-full > div") as HTMLElement;
    expect(bar.style.width).toBe("100%");
  });
});
