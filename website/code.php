<?php $active = 'code'; include('header.php'); ?>

<section class="banner">
    <div class="content">
        <h2>
            Code
        </h2>
    </div>
</section>

<section>
    <div class="content group">
        <div class="tile wide">
            <h3>Grab a copy</h3>

            <p>
                The code is currently hosted on <a href="https://github.com/mikey-austin/greyd">GitHub</a>:
            </p>
            <p>
                <a href="https://github.com/mikey-austin/greyd">github.com/mikey-austin/greyd</a>
            </p>
            <p>
                <em>Greyd</em> uses the Autotools for it's build system, namely:
            </p>
            <ul>
                <li>Autoconf</li>
                <li>Automake</li>
                <li>Libtool</li>
            </ul>
            <p>
                HTML &amp; Roff man pages are generated from markdown source with <a href="http://rtomayko.github.io/ronn/" target="_blank">Ronn</a>.
            </p>
        </div>

        <div class="tile wide">
            <h3>Developers</h3>

            <p>To get started, below is a rough guide to setting up a dev environment:</p>

            <div class="highlight">
<code>$ git clone https://github.com/mikey-austin/greyd.git
$ cd greyd && autoreconf -i
$ ./configure CC="-g -O0" --with-bdb --with-netfilter
$ make check</code>
            </div>

            <p>
                Note, depending on how you <em>configure</em> the build, you may need to set your <em>LD_LIBRARY_PATH</em> to the location of the drivers. For example:
            </p>
            <div class="highlight">
                <code>$ export LD_LIBRARY_PATH="${PWD}/drivers/.libs"</code>
            </div>
            <p>
                To get around the above, you may disable shared libraries when configuring:
            </p>
            <div class="highlight">
                <code>$ ./configure --disable-shared --with-bdb --with-netfilter</code>
            </div>
        </div>
    </div>
</section>

<?php include('footer.php') ?>