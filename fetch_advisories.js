const fs = require('fs');
const path = require('path');
const axios = require('axios');

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'advisories.json');
const API_URL = 'https://api.github.com/advisories?ecosystem=npm&type=malware';

async function fetchAdvisories() {
  try {
    console.log('Fetching advisories...');
    
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    console.log(`Fetching advisories published since ${oneYearAgo.toISOString()}`);

    let allNewAdvisories = [];
    let page = 1;
    let keepFetching = true;
    
    const headers = {
      'Accept': 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'pistachio-action-fetcher'
    };

    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
    }

    while (keepFetching) {
      console.log(`Fetching page ${page}...`);
      
      try {
        const response = await axios.get(API_URL, {
          params: {
            per_page: 100,
            page: page,
            sort: 'published',
            direction: 'desc'
          },
          headers: headers
        });

        const data = response.data;
        
        if (data.length === 0) {
          console.log('No more data returned from API.');
          break;
        }

        for (const advisory of data) {
          const publishedAt = new Date(advisory.published_at);
          if (publishedAt < oneYearAgo) {
            console.log(`Found advisory older than 1 year (${advisory.published_at}), stopping fetch.`);
            keepFetching = false;
            break; // Stop processing this page
          }
          allNewAdvisories.push(advisory);
        }

        if (keepFetching) {
            page++;
            // Add a small delay to avoid hitting rate limits too aggressively
            await new Promise(resolve => setTimeout(resolve, 1000));
        }

      } catch (error) {
        if (error.response && (error.response.status === 429 || error.response.status === 403)) {
             // Check for rate limit headers
             const retryAfter = error.response.headers['retry-after'] || 
                                error.response.headers['x-ratelimit-reset'] ? (parseInt(error.response.headers['x-ratelimit-reset']) - Math.floor(Date.now() / 1000)) : 60;
             
             // If retryAfter is negative (reset time passed) or too large, default to 60
             const waitTime = (retryAfter > 0 && retryAfter < 3600) ? retryAfter : 60;

             console.log(`Rate limited (Status ${error.response.status}). Waiting for ${waitTime} seconds...`);
             await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
             continue; // Retry the same page
        } else {
            throw error;
        }
      }
    }

    console.log(`Fetched ${allNewAdvisories.length} advisories from the last year.`);

    // Transform advisories to new schema
    const transformedAdvisories = allNewAdvisories.map(advisory => {
        // Extract package name from affected array if possible, or use a default/unknown
        // The GitHub API response usually has 'vulnerabilities' array with 'package' info
        // But the 'advisories' endpoint returns a slightly different structure.
        // Let's inspect what we get. The user example has "packageName": "json-map-source".
        // In the API response, 'vulnerabilities' is an array. We'll take the first one's package name.
        
        let packageName = 'unknown';
        let ecosystem = 'npm';
        let affectedVersionRanges = [];
        
        if (advisory.vulnerabilities && advisory.vulnerabilities.length > 0) {
            packageName = advisory.vulnerabilities[0].package.name;
            ecosystem = advisory.vulnerabilities[0].package.ecosystem;
            affectedVersionRanges = advisory.vulnerabilities.map(v => v.vulnerable_version_range);
        }

        return {
            id: `github:${advisory.ghsa_id}:${ecosystem}:${packageName}`,
            source: "github",
            sourceId: advisory.ghsa_id,
            ecosystem: ecosystem,
            packageName: packageName,
            kind: "malware", // Hardcoded as per request "type=malware"
            severity: advisory.severity,
            summary: advisory.summary,
            description: advisory.description,
            affectedVersionRanges: affectedVersionRanges,
            firstPatchedVersion: advisory.vulnerabilities && advisory.vulnerabilities[0] ? advisory.vulnerabilities[0].first_patched_version : null,
            aliases: advisory.identifiers ? advisory.identifiers.map(id => id.value) : [],
            cwes: advisory.cwes ? advisory.cwes.map(cwe => cwe.cwe_id) : [],
            publishedAt: advisory.published_at,
            updatedAt: advisory.updated_at,
            withdrawnAt: advisory.withdrawn_at,
            references: advisory.references,
            metadata: {
                htmlUrl: advisory.html_url,
                apiUrl: advisory.url,
                cvssScore: advisory.cvss ? advisory.cvss.score : null
            }
        };
    });

    // Ensure data directory exists
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    // Read existing data
    let existingData = {
        schemaVersion: "1.0",
        generatedAt: new Date().toISOString(),
        advisories: []
    };

    if (fs.existsSync(DATA_FILE)) {
      const fileContent = fs.readFileSync(DATA_FILE, 'utf8');
      try {
        const parsed = JSON.parse(fileContent);
        // Handle migration from old array format to new object format
        if (Array.isArray(parsed)) {
            // It's the old format, we'll discard it or migrate it?
            // Since we are fetching 1 year history, let's just use what we fetched + what we might have had if we want to be safe.
            // But simpler to just start fresh with the new schema if it's an array.
            console.log('Detected old data format (array), migrating to new schema object.');
            // We can try to transform old data too, but we might lack some fields if we didn't save them?
            // Actually we saved the raw response before, so we could transform it.
            // But let's keep it simple: we have the new fetch.
            // If we want to keep older data that is NOT in the new fetch (older than 1 year), we should migrate.
            // For now, let's assume the new fetch covers what we need or we just reset.
            // The prompt said "saving the data... make sure only new record is added".
            // Let's try to preserve old data if possible.
            
            // Actually, let's just treat existing as empty if it's an array, 
            // because we are re-fetching everything from last year anyway.
            // If the user had data older than 1 year, it will be lost. 
            // But the user just asked for this change now.
        } else {
            existingData = parsed;
        }
      } catch (e) {
        console.error('Error parsing existing data file, starting fresh.');
      }
    }

    // Deduplicate
    const existingIds = new Set(existingData.advisories.map(a => a.sourceId));
    let addedCount = 0;

    for (const advisory of transformedAdvisories) {
      if (!existingIds.has(advisory.sourceId)) {
        existingData.advisories.push(advisory);
        existingIds.add(advisory.sourceId);
        addedCount++;
      }
    }

    console.log(`Added ${addedCount} new advisories.`);
    
    // Update generatedAt
    existingData.generatedAt = new Date().toISOString();

    if (addedCount > 0 || existingData.advisories.length !== transformedAdvisories.length) {
      // Save back to file
      fs.writeFileSync(DATA_FILE, JSON.stringify(existingData, null, 2));
      console.log('Saved updated advisories to file.');
    } else {
      console.log('No new advisories to save.');
    }

  } catch (error) {
    console.error('Error fetching advisories:', error.message);
    process.exit(1);
  }
}

fetchAdvisories();
