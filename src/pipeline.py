import ast
import requests
import yara
from bs4 import BeautifulSoup
import re
import json
import uuid
from dotenv import load_dotenv
from litellm import completion, OpenAIError

# Load environment variables from .env file
load_dotenv()

SECURITY_REPORT_LINKS = [
    "https://cloud.google.com/blog/topics/threat-intelligence/sonicwall-secure-mobile-access-exploitation-overstep-backdoor",
    "https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/",
    "https://cloud.google.com/blog/topics/threat-intelligence/suspected-apt-targets-ivanti-zero-day/",
]

# YARA rules related constants
YARA_RULE_REGEX = r"rule\s+\w+\s*{(?:[^{}]*|{[^{}]*})*}"

# LLM related constants

IOC_TYPES = [
    "ip-address",
    "domain-name",
    "email-address",
    "email-subject",
    "file-name",
    "file-path",
    "hex-string",
    "url",
    "sha256-hash",
    "md5-hash",
]

LLM_IOC_SYSTEM_PROMPT = (
    "You are an expert in cybersecurity. "
    "Your task is to extract all Indicators of Compromise (IOCs) from the provided text. "
    "IOCs include, but are not limited to: Unique Code Sequences (Hex Strings), IP addresses, domain names, email addresses, email subjects, file names, user-agent strings, URLs, usernames, passwords, SHA and MD5 hashes, etc. "
    "Return the IOCs as a JSON array, where each item is an object with keys: 'indicator_type', 'indicator', and 'context'. "
    "The 'indicator_type' value must be one of the following (case sensitive): "
    + ",".join(IOC_TYPES)
    + ". "
    "The 'context' should include information that surrounds the IOC, such as the filename associated with a hash, the type of infrastructure for an IPv4 address, or any other relevant details found near the IOC in the text. "
    'If no IOCs are found, return: {"result": "No IOC Found."} '
    "If IOCs are found, return the JSON array directly without any extra explanation or formatting. "
    "Sample response:\n"
    "[\n"
    "  {\n"
    '    "indicator_type": "ip-address",\n'
    '    "indicator": "193.149.180.50",\n'
    '    "context": "Source of VPN sessions where compromise occurred (used by UNC6148 between at least May 2025 and June 2025)"\n'
    "  },\n"
    "  {\n"
    '    "indicator_type": "sha256-hash",\n'
    '    "indicator": "b28d57269fe4cd90d1650bde5e905611",\n'
    '    "context": "OVERSTEP"\n'
    "  }\n"
    "]"
)

LLM_IOC_USER_PROMPT = "Extract IOCs from the following text:\n"

LLM_YARA_RULE_SYSTEM_PROMPT = (
    "You are an expert in malware detection and YARA rule writing. "
    "Given a list of Indicators of Compromise (IOCs) and their context, your task is to generate YARA rules that can be used to detect files or artifacts related to these IOCs. "
    "Use the IOCs as string or hex patterns in the 'strings' section, and use their context to improve each rule's accuracy if possible. "
    "Include a 'meta' section with a description and any relevant context. "
    "Each rule name should be descriptive and based on the threat or context if possible. "
    "Return the YARA rules as a JSON array, where each item is a string containing a complete YARA rule. "
    "Do not include any extra explanation or formatting outside the JSON array. "
    "Sample input:\n"
    "[\n"
    '  ("ip-address", "193.149.180.50", "Source of VPN sessions"),\n'
    '  ("sha256-hash", "b28d57269fe4cd90d1650bde5e905611", "OVERSTEP")\n'
    "]\n"
    "Sample output:\n"
    "[\n"
    '  "rule OVERSTEP_Detection {\\n'
    "      meta:\\n"
    '          description = \\"Detects artifacts related to OVERSTEP using extracted IOCs\\"\\n'
    "      strings:\\n"
    '          $ip1 = \\"193.149.180.50\\"\\n'
    '          $sha1 = \\"b28d57269fe4cd90d1650bde5e905611\\"\\n'
    "      condition:\\n"
    "          any of them\\n"
    '  }"\n'
    "]"
)

LLM_YARA_RULE_USER_PROMPT = (
    "Construct a YARA rule based on the following IOCs and their context:\n"
)

MAX_TOKENS = 4096


def match_yara_rules(text: str) -> list[str]:
    """
    Extracts YARA rules from the given text using the YARA_RULE_REGEX.
    Returns a list of matched YARA rule strings.
    """
    yara_matches = re.findall(YARA_RULE_REGEX, text, re.DOTALL)
    return yara_matches


def match_and_remove_yara_rules_v2(text: str) -> tuple[list[str], str]:
    """
    Extracts YARA rules from the given text using brace counting.
    Returns a tuple: (list of matched YARA rule strings, text with YARA rules removed).
    """
    rules = []
    lines = text.splitlines()
    in_rule = False
    brace_count = 0
    current_rule = []
    output_lines = []

    for line in lines:
        if not in_rule and line.strip().startswith("rule "):
            in_rule = True
            brace_count = 0
            current_rule = [line]
            brace_count += line.count("{") - line.count("}")
            if brace_count == 0 and "{" in line:
                rules.append("\n".join(current_rule))
                in_rule = False
            continue
        if in_rule:
            current_rule.append(line)
            brace_count += line.count("{") - line.count("}")
            if brace_count == 0:
                rules.append("\n".join(current_rule))
                in_rule = False
            continue
        # Only add lines not part of a YARA rule
        output_lines.append(line)
        # TODO(haozzz): Implement YARA rule compilation if needed
        # yara_rules = []
        # for yara_match in yara_matches:
        #     try:
        #         print(yara_match)  # Debug print to see the matched YARA rule
        #         yara_rules.append(yara.compile(source=yara_match))
        #     except yara.SyntaxError as e:
        #         print(f"YARA rule syntax error: {e}")
        #         continue
        # return yara_rules
    return rules, "\n".join(output_lines)


def extract_content_from_link(webpage_link: str) -> str:
    """
    Fetches and extracts the main textual content from a webpage.
    Returns the extracted text, or an empty string on failure.
    """
    try:
        response = requests.get(webpage_link, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        # Remove script and style elements
        for tag in soup(["script", "style"]):
            tag.decompose()
        # Get text and clean up whitespace
        text = soup.get_text(separator="\n")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines)
    except Exception as e:
        print(f"Failed to retrieve or parse content from {webpage_link}: {e}")
        return


def call_llm(model: str, messages: list[dict]) -> str:
    """
    Calls the LLM with the provided parameters and returns the response.
    """
    try:
        response = completion(
            model=model,
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=0.8,
        )
        return response.choices[0].message.content.strip()
    except OpenAIError as e:
        print(f"Error during LLM call: {e}")
        return ""


def extract_iocs_from_text_using_llm(text: str, link: str) -> list[tuple]:
    """
    Extracts IOCs from the given text using llm.
    """
    response = call_llm(
        model="openai/gpt-4o",
        messages=[
            {"role": "system", "content": LLM_IOC_SYSTEM_PROMPT},
            {"role": "user", "content": LLM_IOC_USER_PROMPT + text},
        ],
    )
    if not response:
        print("No response from LLM.")
        return []
    return parse_and_save_iocs_from_llm_response(link, response)


def parse_and_save_iocs_from_llm_response(
    input_link: str, response_content: str
) -> list[tuple]:
    """
    Parses the LLM response to extract IOCs, and saves them together with the input text in a file.
    Returns a list of tuples in the format: (indicator type, indicator, context).
    """
    print(f"LLM response content: {response_content}")  # Debug print
    iocs = []
    # Join lines if response_content is a list of lines
    if isinstance(response_content, list):
        response_str = "".join(response_content).strip()
    else:
        response_str = response_content.strip()

    print(f"Processed LLM response: {response_str}")  # Debug print

    try:
        json_iocs = json.loads(response_str)
        print(f"Parsed JSON IOC response: {json_iocs}")  # Debug print
        # If the response is a dict with "result": "No IOC Found."
        if isinstance(json_iocs, dict) and json_iocs.get("result") == "No IOC Found.":
            iocs = ["No IOC Found."]
        # Otherwise, parse the list of IOC dicts
        for item in json_iocs:
            iocs.append(
                (
                    item.get("indicator_type", ""),
                    item.get("indicator", ""),
                    item.get("context", ""),
                )
            )
    except Exception as e:
        print(f"Failed to parse JSON IOC response: {e}")
    # Save the input link and IOCs to a file
    filename = f"./src/llm-output/iocs/llm_ioc_output_{uuid.uuid4().hex}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(
            {"input_link": input_link, "output_iocs": iocs},
            f,
            ensure_ascii=False,
            indent=2,
        )
    return iocs


def construct_and_save_yara_rule_from_iocs(
    iocs: list[tuple], golden_rules: list[str], link: str
):
    # Step 1 - Filter IOCs to only include those that can be used in YARA rules
    filtered_iocs = [ioc for ioc in iocs if ioc[0].lower() in IOC_TYPES]
    # Step 2 - Use LLM to construct a YARA rule from the filtered IOCs
    if not filtered_iocs:
        print("No valid IOCs found for YARA rule construction.")
        return
    # Calls the LLM
    response = call_llm(
        model="openai/gpt-4o",
        messages=[
            {"role": "system", "content": LLM_YARA_RULE_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": LLM_YARA_RULE_USER_PROMPT
                + ",".join(str(ioc) for ioc in filtered_iocs),
            },
        ],
    )
    if not response:
        print("No response from LLM.")
        return []
    # Parse the response to get the YARA rule
    try:
        yara_rules = response.strip()
        print(f"Constructed YARA rule: {yara_rules}")  # Debug print
    except Exception as e:
        print(f"Failed to parse YARA rule from LLM response: {e}")
        return
    # Step 3 - Save the constructed and golden YARA rule to a file
    # Save the input link and IOCs to a file
    filename = f"./src/llm-output/yara-rules/yara_rules_output_{uuid.uuid4().hex}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(
            {"golden_rules": golden_rules, "output_rules": yara_rules},
            f,
            ensure_ascii=False,
            indent=2,
        )
    return iocs


def run_pipeline():
    print("Running the pipeline...")

    for link in SECURITY_REPORT_LINKS:
        # Step 1 - Extracts content from security report links
        print(f"Extracting content from: {link}")
        content = extract_content_from_link(link)
        print(f"Extracted content length: {len(content)} characters")

        # Step 2 - Try to match and remove golden YARA rules against the extracted content.
        golden_yara_rules, content_without_golden_rules = (
            match_and_remove_yara_rules_v2(content)
        )
        print(f"Found {len(golden_yara_rules)} YARA rules in the content.")

        # Step 3 - If no existing YARA rules match, use LLM to extract IOCs
        iocs = extract_iocs_from_text_using_llm(
            text=content_without_golden_rules, link=link
        )
        print(f"Extracted {len(iocs)} IOCs from the content.")
        print(
            f"Remove golden yara rules content length: {len(content_without_golden_rules)} characters"
        )

        # Step 4 - Constructs and saves YARA rules based on the extracted IOCs
        construct_and_save_yara_rule_from_iocs(
            iocs=iocs, golden_rules=golden_yara_rules, link=link
        )

    print("Pipeline completed.")


def main():
    run_pipeline()


if __name__ == "__main__":
    main()
