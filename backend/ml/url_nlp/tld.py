"""tldextract configured to use its bundled public-suffix snapshot only.

By default tldextract downloads the live suffix list on first use. On a hosted
box that adds latency and an outbound dependency to every cold start, so we
pin it to the snapshot shipped with the package.
"""
import tldextract

try:
    extract = tldextract.TLDExtract(suffix_list_urls=())
except AttributeError:  # test doubles that only provide extract()
    extract = tldextract.extract
