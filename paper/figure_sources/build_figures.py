"""Retained journal figure drawing code, with portable inputs and separate output.
The checked-in paper PDFs remain the authoritative manuscript assets.
"""
from pathlib import Path
import hashlib
import json
import math
import subprocess
from datetime import datetime, timezone
import sys
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor
import pdfplumber
from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[1]
OLD = HERE
VERIFIED = REPOSITORY / "data/paper_reference_metrics.json"
MM = 72 / 25.4
WIDTH = 31 * 12 * 72 / 72.27
FONT_MIN = 8.1
BLUE, ORANGE, GRAY = '#0072B2', '#D55E00', '#656B73'
TEXT_ORANGE = '#A84300'
INK, LIGHT, WHITE = '#202A35', '#CFD5DB', '#FFFFFF'
PALE_BLUE, PALE_ORANGE, PALE_GRAY = '#ECF4FA', '#FCF0E9', '#F1F3F5'
pdfmetrics.registerFont(TTFont('JournalArial', r'C:\Windows\Fonts\arial.ttf')) if Path(r'C:\Windows\Fonts\arial.ttf').exists() else pdfmetrics.registerFont(pdfmetrics.Font('JournalArial', 'Helvetica', 'WinAnsiEncoding'))
pdfmetrics.registerFont(TTFont('JournalArialBold', r'C:\Windows\Fonts\arialbd.ttf')) if Path(r'C:\Windows\Fonts\arialbd.ttf').exists() else pdfmetrics.registerFont(pdfmetrics.Font('JournalArialBold', 'Helvetica-Bold', 'WinAnsiEncoding'))
CASES = ['AURORA-CHAIN-001', 'AURORA-CHAIN-002', 'AEL-WIZARD-EMOTET-001',
         'AEL-MUSTANG-PANDA-PLUGX-001', 'AEL-CARBANAK-RAT-001',
         'AEL-OILRIG-SIDETWIST-001', 'AEL-SANDWORM-EXARAMEL-WIN-001',
         'MEP-WINDOWS-WEBSHELL-01']
SHORT = dict(zip(CASES, ['Aurora-001', 'Aurora-002', 'Emotet', 'PlugX',
                        'Carbanak', 'SideTwist', 'Exaramel', 'Webshell']))

def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class Figure:
    def __init__(self, name, height_mm, title):
        self.name, self.h = name, height_mm * MM
        self.page_h = self.h - 28
        self.old = {}
        self.c = canvas.Canvas(str(HERE / (name + '.pdf')), pagesize=(WIDTH, self.page_h), initialFontName='JournalArial')
        self.c.setTitle(title)
        self.c.setAuthor('Anonymous C2Trace draft')
        self.text_records = []

    def text(self, x, y, text, size=FONT_MIN, color=INK, bold=False, align='left'):
        assert size >= FONT_MIN
        if color == ORANGE:
            color = TEXT_ORANGE
        font = 'JournalArialBold' if bold else 'JournalArial'
        tw = pdfmetrics.stringWidth(text, font, size)
        left = x - (tw / 2 if align == 'center' else tw if align == 'right' else 0)
        assert left >= 0 and left + tw <= WIDTH + .001, (self.name, text, left, tw)
        assert y - size >= 28 and y + size * .3 <= self.h, (self.name, text, y)
        self.c.setFillColor(HexColor(color))
        self.c.setFont(font, size)
        self.c.drawString(left, self.h - y, text)
        self.text_records.append(dict(text=text, x=left, y=y, width=tw, size=size))

    def paragraph(self, x, y, width, text, size=FONT_MIN, color=INK, bold=False, leading=10.5):
        font = 'JournalArialBold' if bold else 'JournalArial'
        lines = []
        for part in text.split('\n'):
            line = ''
            for word in part.split():
                candidate = (line + ' ' + word).strip()
                if pdfmetrics.stringWidth(candidate, font, size) <= width:
                    line = candidate
                else:
                    assert line, (self.name, word, width)
                    lines.append(line)
                    line = word
            lines.append(line)
        for i, line in enumerate(lines):
            if line:
                self.text(x, y + i * leading, line, size, color, bold)
        return len(lines) * leading

    def line(self, x1, y1, x2, y2, color=GRAY, width=.7, dash=None):
        self.c.setStrokeColor(HexColor(color))
        self.c.setLineWidth(width)
        self.c.setDash(dash or [])
        self.c.line(x1, self.h-y1, x2, self.h-y2)
        self.c.setDash([])

    def rect(self, x, y, w, h, fill=WHITE, stroke=GRAY, width=.7):
        self.c.setFillColor(HexColor(fill))
        self.c.setStrokeColor(HexColor(stroke))
        self.c.setLineWidth(width)
        self.c.rect(x, self.h-y-h, w, h, fill=1, stroke=1)

    def box(self, x, y, w, h, title, body='', color=BLUE, fill=PALE_BLUE):
        self.rect(x, y, w, h, fill, color)
        ht = self.paragraph(x+7, y+14, w-14, title, 8.6, color, True, 10.5)
        hb = self.paragraph(x+7, y+14+ht+3, w-14, body) if body else 0
        assert 14 + ht + 3 + hb <= h + 8, (self.name, title, ht, hb, h)

    def arrow(self, x1, y1, x2, y2, color=BLUE, dash=None):
        self.line(x1, y1, x2, y2, color, .8, dash)
        a = math.atan2(y2-y1, x2-x1)
        path = self.c.beginPath()
        path.moveTo(x2, self.h-y2)
        for sign in [-1, 1]:
            path.lineTo(x2-4.5*math.cos(a+sign*.45), self.h-(y2-4.5*math.sin(a+sign*.45)))
        path.close()
        self.c.setFillColor(HexColor(color))
        self.c.drawPath(path, fill=1, stroke=0)

    def hatch(self, x, y, w, h, color=ORANGE):
        k = 6
        while k < w+h:
            x1, x2 = max(0, k-h), min(w, k)
            self.line(x+x1, y+k-x1, x+x2, y+k-x2, color, .4)
            k += 6

    def marker(self, x, y, system):
        self.c.setFillColor(HexColor(BLUE if system == 'c2trace' else ORANGE))
        self.c.setStrokeColor(HexColor(BLUE if system == 'c2trace' else ORANGE))
        if system == 'c2trace':
            self.c.circle(x, self.h-y, 3, fill=1, stroke=1)
        else:
            p = self.c.beginPath()
            p.moveTo(x, self.h-(y-4))
            p.lineTo(x-4, self.h-(y+3))
            p.lineTo(x+4, self.h-(y+3))
            p.close()
            self.c.drawPath(p, fill=1, stroke=1)

    def legend(self, y):
        self.marker(105, y-3, 'c2trace')
        self.text(115, y, 'C2Trace')
        self.marker(209, y-3, 'react')
        self.text(219, y, 'Public ReAct')

    def save(self, numeric_inputs=None):
        self.c.showPage()
        self.c.save()
        with pdfplumber.open(HERE / (self.name+'.pdf')) as doc:
            assert len(doc.pages) == 1
            page = doc.pages[0]
            minimum = min(c['size'] for c in page.chars if c['text'].strip())
            assert minimum >= FONT_MIN - .001, (self.name, minimum)
            assert all(c['x0'] >= -.01 and c['x1'] <= WIDTH+.01 and c['top'] >= -.01
                       and c['bottom'] <= self.page_h+.01 for c in page.chars)
            extracted = page.extract_text()
        for i, a in enumerate(self.text_records):
            for b in self.text_records[i+1:]:
                if abs(a['y']-b['y']) < .7 * min(a['size'], b['size']):
                    assert min(a['x']+a['width'], b['x']+b['width']) <= max(a['x'], b['x'])+.1, (self.name, a['text'], b['text'])
        old_pdf = OLD / (self.name+'.pdf')
        record = dict(figure=self.name, dimensions_mm=dict(width=WIDTH/MM, height=self.page_h/MM),
                      minimum_font_bp=minimum, font_embedding='Embedded Arial / Arial Bold TrueType subsets',
                      original_sources_manifest_sha256=sha(OLD/(self.name+'_sources.json')),
                      original_figure_sha256=sha(old_pdf), original_inputs=self.old['inputs'],
                      original_caption=self.old['caption'], output_sha256=sha(HERE/(self.name+'.pdf')),
                      generator_sha256=sha(Path(__file__)), text_within_canvas=True,
                      text_elements_nonoverlapping=True, visual_review='pending')
        if numeric_inputs is not None:
            record['rendered_numeric_inputs'] = numeric_inputs
        (HERE/(self.name+'_sources.json')).write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        (HERE/(self.name+'_text.txt')).write_text(extracted+'\n', encoding='utf8')
        return record

def motivation():
    f = Figure('figure01_motivation', 126, 'From a network alert to exact host objects')
    f.text(10, 43, 'AURORA-CHAIN-002: observed dual-process case', color=GRAY)
    f.box(10, 55, WIDTH-20, 38, 'Alert seed', 'Network tuple + time; no process or file identity', GRAY, PALE_GRAY)
    for x, alias in [(10, 'P1'), (198, 'P2')]:
        f.arrow(WIDTH/2, 94, x+81, 108)
        f.box(x, 108, 162.61, 49, 'Live flow owner: process '+alias,
              'Owns a live connection; observed payload path')
        f.arrow(x+81, 158, WIDTH/2, 172)
    f.box(10, 172, WIDTH-20, 39, 'Shared file', 'One verified payload is associated with both processes')
    f.arrow(WIDTH/2, 212, 63.5, 230)
    for x, w, title, body in [(10, 107, 'Evidence audit', 'Rules + target recheck'),
                              (132, 107, 'Authorized actions', 'Terminate P1/P2; remove file'),
                              (254, 106.61, 'Fresh PostState', 'Query actual host outcome')]:
        f.box(x, 230, w, 59, title, body)
    f.arrow(117, 260, 132, 260)
    f.arrow(239, 260, 254, 260)
    f.line(10, 305, WIDTH-10, 305, LIGHT)
    f.paragraph(10, 320, WIDTH-20,
                'Ground Truth: external scoring only. Identifiers use object aliases. Live observed relations are not all scorer-credited trace facts.', color=GRAY)
    return f.save()

def protocol():
    f = Figure('figure03_response_protocol', 146, 'Two-stage investigation and response')
    f.text(10, 44, 'RUN 1: NO HOST MODIFICATION', 8.6, BLUE, True)
    cards = [('1  Investigate', 'Live read-only evidence'), ('2  Plan + audit', 'Hard-rule decision'),
             ('3  Dry-run', 'Rehearse exact proposed objects'), ('4  External gate', 'Review target identity and safety')]
    for i, (title, body) in enumerate(cards):
        x, y = 10+(i%2)*188, 54+(i//2)*59
        f.box(x, y, 162.61, 45, title, body)
    f.arrow(173, 76, 198, 76)
    f.arrow(173, 135, 198, 135)
    f.line(279, 99, 279, 106, BLUE)
    f.line(279, 106, 91, 106, BLUE)
    f.arrow(91, 106, 91, 113)
    f.text(10, 181, 'RUN 2: REPLAY STRATEGY; REFRESH EVIDENCE', 8.6, BLUE, True)
    cards = [('1  Refresh + reaudit', 'Live objects vs reviewed target'),
             ('2  Authorize current call', 'New single-use; case + action + args + lock'),
             ('3  Verify + revalidate', 'Primary identity / path / hash'),
             ('4  Consume nonce; act', 'Consume before exact tool action; no target substitution'),
             ('5  Fresh PostState', 'New queries after the response'),
             ('6  Record result', 'Success / partial / failed')]
    for i, (title, body) in enumerate(cards):
        x, y = 10+(i%2)*188, 193+(i//2)*50
        f.box(x, y, 162.61, 42, title, body)
    for y in [214, 264, 314]:
        f.arrow(173, y, 198, y)
    for bottom in [235, 285]:
        f.line(279, bottom, 279, bottom+4, BLUE)
        f.line(279, bottom+4, 91, bottom+4, BLUE)
        f.arrow(91, bottom+4, 91, bottom+8)
    f.line(10, 347, WIDTH-10, 347, LIGHT)
    f.paragraph(10, 363, WIDTH-20,
                'FAIL CLOSED: mismatch, path/hash drift, protection conflict or replay blocks action. Missing fresh PostState prevents verified success.', color=ORANGE, bold=True)
    f.paragraph(10, 388, WIDTH-20,
                'External cleanup is separate. Secondary PID execution-time validation is weaker; no all-object TOCTOU guarantee.', color=GRAY)
    return f.save()

def pipeline():
    f = Figure('figure04_evidence_pipeline', 129, 'Four evaluation streams; separate execution and scoring')
    i = f.old['inputs']
    f.box(10, 43, WIDTH-20, 40, 'Public source + case lock; attack instance + sensors',
          'Frozen case semantics; Suricata and Windows evidence', GRAY, PALE_GRAY)
    f.arrow(WIDTH/2, 84, WIDTH/2, 98)
    f.box(10, 98, WIDTH-20, 42, 'Runtime evidence boundary',
          'Sanitized runtime input; Ground Truth excluded. Safety metadata: controller checks only')
    f.arrow(WIDTH/2, 142, WIDTH/2, 158)
    rows = [('Effect round', f"{i['rq1_case_count']} cases; one run/case", 'Live response + fresh PostState', BLUE),
            ('Paired baseline', f"{i['baseline_slots']} slots; {i['baseline_paired_blocks']} paired blocks", 'Live response + fresh PostState', ORANGE),
            ('LLM-Direct SetB', f"{i['direct_cases']} cases; 1 LLM call/case", 'Proposal only; 0 tool calls', GRAY),
            ('RQ3 ablation', f"{i['ablation_cells']} cells; 1 smoke run/cell", 'Descriptive smoke results', BLUE)]
    for n, (title, count, outcome, color) in enumerate(rows):
        y = 160+n*39
        f.rect(10, y, WIDTH-20, 34, PALE_GRAY, color)
        f.text(17, y+13, title, 8.6, color, True)
        f.text(17, y+26, count)
        f.line(174, y+6, 174, y+29, LIGHT)
        f.text(184, y+13, outcome)
        f.text(184, y+26, 'External score + offline closure', color=GRAY)
    f.paragraph(10, 332, WIDTH-20,
                'External Ground Truth supports scoring and cleanup, with no model-input route. Full prompt-body/per-call audit coverage remains partial.', color=GRAY)
    return f.save()

def baseline(data):
    f = Figure('figure05_baseline_f1', 118, 'Main live baseline: case macro and pooled micro F1')
    b = data['baseline']
    numbers = []
    for n, (metric, title) in enumerate([('trace', '(a) Trace'), ('response', '(b) Response Action')]):
        top = 65+n*116
        x, w, h = 42, WIDTH-54, 72
        f.text(10, top-21, title, 8.8, bold=True)
        f.text(x, top-9, 'F1', color=GRAY)
        for tick in [0, .25, .5, .75, 1]:
            yy = top+h*(1-tick)
            f.line(x, yy, x+w, yy, LIGHT, .5)
            f.text(x-7, yy+3, f'{tick:g}', color=GRAY, align='right')
        f.line(x, top, x, top+h)
        for j, (agg, label) in enumerate([('macro', 'Case macro'), ('pooled_micro', 'Pooled micro')]):
            center = x+77+j*154
            for k, system in enumerate(['c2trace', 'react']):
                node = b[agg][system][metric]['f1']
                val = node['value'] if isinstance(node, dict) else node
                xx = center-34+k*39
                f.rect(xx, top+h*(1-val), 32, h*val, BLUE if not k else PALE_ORANGE, BLUE if not k else ORANGE)
                if k:
                    f.hatch(xx, top+h*(1-val), 32, h*val)
                f.text(xx+16, top+h*(1-val)-5, f'{val:.3f}', color=BLUE if not k else ORANGE, bold=True, align='center')
                numbers.append(dict(metric=metric, aggregation=agg, system=system, value=val, label=f'{val:.3f}'))
            f.text(center+1, top+h+14, label, align='center')
    f.legend(290)
    f.paragraph(10, 309, WIDTH-20,
                '48 logical slots; 24 paired blocks. ReAct response macro: valid F1 in 7/8 cases; null values retained. Action F1 differs from PostState success.', color=GRAY)
    return f.save(numbers)

def robustness(data):
    f = Figure('figure06_case_trace_and_cost', 156, 'Per-case trace variation and mean runtime cost')
    b = data['baseline']
    f.text(10, 44, '(a) Per-case pooled Trace F1', 8.8, bold=True)
    f.legend(61)
    x, w = 98, WIDTH-111
    for tick in [0, .25, .5, .75, 1]:
        xx = x+tick*w
        f.line(xx, 77, xx, 221, LIGHT, .5)
        f.text(xx, 236, f'{tick:g}', color=GRAY, align='center')
    plotted = []
    for n, case in enumerate(CASES):
        yy = 84+n*18
        f.text(x-8, yy+3, SHORT[case], align='right')
        vals = [b['per_case'][case][s]['trace']['f1'] for s in ['c2trace', 'react']]
        if all(v is not None for v in vals):
            f.line(x+vals[0]*w, yy, x+vals[1]*w, yy)
        for off, system, val in [(-2, 'c2trace', vals[0]), (2, 'react', vals[1])]:
            if val is None:
                f.text(x, yy+3, 'N/A', color=GRAY)
            else:
                f.marker(x+val*w, yy+off, system)
            plotted.append(dict(case=case, system=system, trace_f1=val))
    f.text(x+w/2, 251, 'Trace F1', color=GRAY, align='center')
    f.text(10, 277, '(b) Mean per selected trial; n = 24/system', 8.8, bold=True)
    for n, (field, label, scale) in enumerate([('llm_calls', 'LLM calls', 1), ('tool_calls', 'Tool calls', 1), ('total_tokens', 'Tokens (thousands)', 1000)]):
        y = 298+n*45
        chartx, chartw = 110, 202
        vals = [b['cost'][s]['mean'][field]/scale for s in ['c2trace', 'react']]
        limit = max(vals)*1.2
        f.text(10, y+9, label)
        for j, system in enumerate(['c2trace', 'react']):
            length = chartw*vals[j]/limit
            by = y+j*13
            f.rect(chartx, by, length, 9, BLUE if not j else PALE_ORANGE, BLUE if not j else ORANGE)
            if j:
                f.hatch(chartx, by, length, 9)
            f.text(chartx+length+5, by+8, f'{vals[j]:.2f}', color=BLUE if not j else ORANGE)
            plotted.append(dict(field=field, system=system, raw_mean=b['cost'][system]['mean'][field], divisor=scale, label=f'{vals[j]:.2f}'))
        f.line(chartx, y+27, chartx+chartw, y+27)
        f.text(chartx, y+39, '0', color=GRAY)
        f.text(chartx+chartw, y+39, f'{limit:.1f}', color=GRAY, align='right')
    f.text(10, 438, 'Separate zero-based scales; connectors show pairs, not uncertainty.', color=GRAY)
    return f.save(plotted)

def blend(value):
    base, target = (244, 248, 251), (0, 114, 178)
    return '#'+''.join(f'{round(base[i]*(1-value)+target[i]*value):02x}' for i in range(3))

def luminance(color):
    rgb = [int(color[i:i+2], 16)/255 for i in [1, 3, 5]]
    linear = [v/12.92 if v <= .04045 else ((v+.055)/1.055)**2.4 for v in rgb]
    return sum(a*b for a, b in zip(linear, [.2126, .7152, .0722]))

def contrasting_label(fill):
    lum = luminance(fill)
    white_ratio = 1.05/(lum+.05)
    black_ratio = (lum+.05)/.05
    color, ratio = (WHITE, white_ratio) if white_ratio >= 4.5 else ('#000000', black_ratio)
    assert ratio >= 4.5
    return color, ratio

def ablation(data):
    f = Figure('figure07_ablation_heatmap', 158, 'RQ3 descriptive ablation: one smoke-mode run per cell')
    a = data['ablation']
    plotted = []
    for n, (metric, title) in enumerate([('trace', '(a) Trace F1'), ('response', '(b) Response Action F1')]):
        title_y, header_y, grid_y = 44+n*163, 58+n*163, 69+n*163
        f.text(10, title_y, title, 8.8, bold=True)
        gridx, cw, ch = 103, 62, 14.5
        for j, variant in enumerate(['A1', 'A2', 'A3', 'A4']):
            f.text(gridx+j*cw+cw/2, header_y, variant, 8.6, bold=True, align='center')
        for i, case in enumerate(CASES):
            yy = grid_y+i*ch
            f.text(gridx-7, yy+10.5, SHORT[case], align='right')
            for j, variant in enumerate(['A1', 'A2', 'A3', 'A4']):
                xx = gridx+j*cw
                val = a['per_case'][case][variant][metric]['f1']
                fill = PALE_GRAY if val is None else blend(val)
                f.rect(xx, yy, cw, ch, fill, WHITE)
                if val is None:
                    f.hatch(xx, yy, cw, ch, GRAY)
                    # A small quiet patch prevents hatch strokes crossing glyphs.
                    f.c.setFillColor(HexColor(PALE_GRAY))
                    f.c.rect(xx+cw/2-11, f.h-(yy+12), 22, 11, fill=1, stroke=0)
                label = 'N/A' if val is None else f'{val:.2f}'
                label_color, ratio = contrasting_label(fill)
                f.text(xx+cw/2, yy+10.5, label, color=label_color, bold=True, align='center')
                plotted.append(dict(metric=metric, case=case, variant=variant, value=val, label=label,
                                    fill=fill, label_color=label_color, contrast_ratio=ratio))
    f.paragraph(10, 369, WIDTH-20, 'A1: no Auditor; A2: no target binding; A3: no Precheck; A4: no PostVerify.', color=GRAY)
    f.paragraph(10, 391, WIDTH-20, 'Trace N/A: empty prediction denominator. Response N/A: no action proposal. Hatched null values are never zero.', color=GRAY)
    f.paragraph(10, 424, WIDTH-20, 'A2 null and A4 = 1.00 are descriptive observations. A4 has no PostVerify; one repetition gives no significance or causal conclusion.', color='#A64800')
    return f.save(plotted)




def _save_pdf(self, numeric_inputs=None):
    self.c.showPage()
    self.c.save()
    return {"figure": self.name}

Figure.save = _save_pdf

def provenance():
    f = Figure('figure08_provenance', 123, 'Valid-trial eligibility and reproducible aggregation')
    f.text(10, 44, '48 valid logical slots / 24 case-and-repetition pairs', 8.6, bold=True)
    f.box(10, 57, 162.61, 54, '1  Eligibility', 'Symmetric service and setup validity; retain normal-output failures')
    f.box(198, 57, 162.61, 54, '2  Unique selection', 'One valid Run per logical slot; three per case and system')
    f.arrow(173, 83, 198, 83)
    f.box(10, 132, 162.61, 54, '3  Original observations', 'Score, classification, usage and independent fresh PostState')
    f.box(198, 132, 162.61, 54, '4  Offline metric checks', 'Reconcile records; recompute TP / FP / FN and denominators')
    f.arrow(173, 159, 198, 159)
    f.line(279, 111, 279, 121, BLUE); f.line(279, 121, 91, 121, BLUE); f.arrow(91, 121, 91, 132)
    f.box(10, 207, WIDTH-20, 42, '5  Separate aggregation levels', 'Pool within each case for case macro; pool all counts for micro')
    f.arrow(279, 186, 279, 207)
    f.text(10, 270, 'Interpretation boundaries', 8.6, color=GRAY, bold=True)
    f.paragraph(10, 285, WIDTH-20, 'Action F1, trial classification and fresh PostState are different outcomes. Logical pairs need not be contemporaneous runs.', color=GRAY)
    f.paragraph(10, 318, WIDTH-20, 'Complete prompt-body capture remains unavailable. Offline consistency does not equal full input replay or a new scorer execution.', color=GRAY)
    return f.save()

def main():
    import argparse
    global HERE
    parser = argparse.ArgumentParser(description="Render retained figure layouts into a separate output directory")
    parser.add_argument('--output', type=Path, default=REPOSITORY/'results/figures')
    args = parser.parse_args()
    data = load(VERIFIED)
    HERE = args.output.resolve()
    HERE.mkdir(parents=True, exist_ok=True)
    for draw in [motivation, protocol, pipeline]: draw()
    for draw in [baseline, robustness, ablation]: draw(data)
    provenance()
    print(HERE)

if __name__ == '__main__': main()
